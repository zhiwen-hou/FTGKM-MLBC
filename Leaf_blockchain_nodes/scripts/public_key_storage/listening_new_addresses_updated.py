from brownie import PublicKeyStorage, accounts, web3
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
import threading
import base64
from scripts.group_key_management.distribute import (
    distribute_new_addresses,
)
from scripts.configure_basic_parameters.addresses_and_ips import get_addresses
from scripts.group_key_management.store import store_group_key
from scripts.configure_basic_parameters.sec_key_utils import (
    get_self_chain_public_keys,
    my_load_private_key,
)


# Monitor blockchain node change eventsMonitor blockchain node change events
def new_addresses_updated_listener(account_num, lock):
    account = accounts[account_num]
    public_key_storage = PublicKeyStorage[-1]
    event_name = "SelfAddressesUpdated"
    event_filter = public_key_storage.events[event_name].create_filter(
        fromBlock="latest"
    )
    print(f"Listening for '{event_name}' events...")
    while True:
        for event in event_filter.get_new_entries():
            changed_time = event.args.changedTime
            changed_address = event.args.changedAddress

            if changed_address == account.address:
                group_key = Fernet.generate_key()
                group_key_hash = web3.solidity_keccak(["bytes"], [group_key])

                encrypted_group_keys = []
                self_addresses = get_addresses()
                self_public_keys = get_self_chain_public_keys()
                account_num_str = str(account_num).zfill(2)
                private_key = my_load_private_key(account_num_str)
                for i in len(self_addresses):
                    self_public_key = serialization.load_pem_public_key(
                        self_public_keys[i]
                    )
                    shared_key = private_key.exchange(ec.ECDH(), self_public_key)
                    derived_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=group_key_hash,
                    ).derive(shared_key)
                    derived_key_base64 = base64.urlsafe_b64encode(derived_key)
                    derived_key_fernet = Fernet(derived_key_base64)
                    encrypted_group_key = derived_key_fernet.encrypt(group_key)
                    encrypted_group_keys.append(encrypted_group_key)

                received_data = ["address changed"]
                store_group_key(
                    received_data,
                    group_key_hash,
                    self_addresses,
                    encrypted_group_keys,
                    account,
                    lock,
                )
            else:
                # Get a list of addresses and select the addresses that have not changed
                self_addresses = get_addresses()
                not_changed_addresses = self_addresses
                if changed_address in not_changed_addresses:
                    not_changed_addresses.remove(changed_address)

                changed_address_hash = web3.solidity_keccak(
                    ["address"], [changed_address]
                )
                send_message_hash = web3.solidity_keccak(
                    ["uint256", "bytes32"], [changed_time, changed_address_hash]
                )
                hash_int = int.from_bytes(send_message_hash, byteorder="big")
                not_changed_addresses_length = len(not_changed_addresses)
                require_num = int((not_changed_addresses_length - 1) / 3 + 1)
                start_index = hash_int % not_changed_addresses_length
                choose_addresses = []
                for i in range(require_num):
                    choose_addresses.append(
                        not_changed_addresses[
                            (start_index + i) % not_changed_addresses_length
                        ]
                    )

                if account.address in choose_addresses:
                    thread_distribute_new_addresses = threading.Thread(
                        target=distribute_new_addresses,
                        args=(
                            changed_time,
                            changed_address,
                            changed_address_hash,
                            send_message_hash,
                            account,
                            account_num,
                        ),
                    )
                    thread_distribute_new_addresses.start()


def main():
    new_addresses_updated_listener()


if __name__ == "__main__":
    main()

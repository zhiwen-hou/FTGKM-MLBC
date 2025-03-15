# Listen for group key update completion events

from brownie import GroupKeyManagement, accounts, web3
import threading
from scripts.group_key_management.distribute import (
    distribute_group_key,
)
from scripts.configure_basic_parameters.addresses_and_ips import get_addresses


def group_key_updated_listener(account_num):
    account = accounts[account_num]
    group_key_management = GroupKeyManagement[-1]
    event_name = "GroupKeyUpdated"
    event_filter = group_key_management.events[event_name].create_filter(
        fromBlock="latest"
    )
    print(f"Listening for '{event_name}' events...")
    while True:
        for event in event_filter.get_new_entries():
            # Extract the group key hash from the event
            group_key_hash = event.args.groupKeyHash
            group_key_updated_time = event.args.updatedTime

            # Calculating hash tables
            send_message_hash = web3.solidity_keccak(
                ["uint256", "bytes32"], [group_key_updated_time, group_key_hash]
            )
            hash_int = int.from_bytes(send_message_hash, byteorder="big")
            self_addresses = get_addresses()
            self_addresses_length = len(self_addresses)
            require_num = int((self_addresses_length - 1) / 3 + 1)
            start_index = hash_int % self_addresses_length
            choose_addresses = []
            for i in range(require_num):
                choose_addresses.append(
                    self_addresses[(start_index + i) % self_addresses_length]
                )

            # If it is in the selected address, forward it
            if account.address in choose_addresses:
                # Distribute group keys
                thread_send_merge_hash_to_parent = threading.Thread(
                    target=distribute_group_key,
                    args=(
                        group_key_hash,
                        group_key_updated_time,
                        send_message_hash,
                        account,
                        account_num,
                    ),
                )

                thread_send_merge_hash_to_parent.start()


def main():
    group_key_updated_listener()


if __name__ == "__main__":
    main()

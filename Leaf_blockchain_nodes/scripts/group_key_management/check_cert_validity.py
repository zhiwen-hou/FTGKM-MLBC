# Validity period of equipment certificates within the testing group

from brownie import accounts, GroupKeyManagement, web3
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
import datetime
import time
import base64
from scripts.configure_basic_parameters.addresses_and_ips import get_addresses
from scripts.group_key_management.store import store_group_key
from scripts.configure_basic_parameters.sec_key_utils import (
    get_self_chain_public_keys,
    my_load_private_key,
)


def check_cert_validity(account_num, lock):
    account = accounts[account_num]
    group_key_management = GroupKeyManagement[-1]
    device_addresses = group_key_management.getDeviceAddresses(
        {"from": account, "required_confs": 0}
    )

    while True:
        # Detection cycle
        time.sleep(60 * 60 * 24)

        # Get the device address of the expired certificate
        invalid_addresses = []
        now_timestamp = int(datetime.datetime.today().timestamp())
        for device_address in device_addresses:
            device_not_valid_after = group_key_management.getDeviceNotValidAfter(
                device_address, {"from": account, "required_confs": 0}
            )
            if now_timestamp > device_not_valid_after:
                invalid_addresses.append(device_address)

        # If there is an expired device certificate,
        # remove it from the group and update the group key
        if len(invalid_addresses) > 0:
            # Generate a group key and a hash of the group key
            group_key_hash_is_exist = True
            while group_key_hash_is_exist is True:
                group_key = Fernet.generate_key()
                group_key_hash = web3.solidity_keccak(["bytes"], [group_key])
                # Determine whether the group key has been used, and if so, regenerate the group key
                group_key_hash_is_exist = group_key_management.groupKeyHashIsExist(
                    group_key_hash, {"from": account, "required_confs": 0}
                )

            # Encrypt the group key using the shared key of each blockchain node
            encrypted_group_keys = []
            self_addresses = get_addresses()
            self_public_keys = get_self_chain_public_keys()
            account_num_str = str(account_num).zfill(2)
            private_key = my_load_private_key(account_num_str)
            for i in range(len(self_addresses)):
                self_public_key = serialization.load_pem_public_key(self_public_keys[i])
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

            received_data = ["cert invalid", invalid_addresses]

            store_group_key(
                received_data,
                group_key_hash,
                self_addresses,
                encrypted_group_keys,
                account,
                lock,
            )

# Distribute group keys

from brownie import GroupKeyManagement, web3
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import socket
import pickle
import threading
import random
import base64
from scripts.configure_basic_parameters.adjacent_chains import SELF_CHAIN_ID
from scripts.configure_basic_parameters.sec_key_utils import my_load_private_key
from eth_account.messages import encode_defunct


def distribute_group_key(
    group_key_hash,
    group_key_updated_time,
    send_message_hash,
    account,
    account_num,
):
    group_key_management = GroupKeyManagement[-1]

    # Get the group key
    generator_public_key_bytes, encrypted_group_key = (
        group_key_management.getEncryptedGroupKey(
            group_key_hash, account.address, {"from": account, "required_confs": 0}
        )
    )
    account_num_str = str(account_num).zfill(2)
    self_private_key = my_load_private_key(account_num_str)
    generator_public_key = serialization.load_pem_public_key(generator_public_key_bytes)
    shared_key = self_private_key.exchange(ec.ECDH(), generator_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=group_key_hash,
    ).derive(shared_key)
    derived_key_base64 = base64.urlsafe_b64encode(derived_key)
    derived_key_fernet = Fernet(derived_key_base64)
    try:
        group_key = derived_key_fernet.decrypt(encrypted_group_key)
    except:
        print(f"{account_num}-The decrypted group_key is incorrect: {group_key_hash}")
    else:
        # Verify that the hash of the group key is correct
        decrypt_group_key_hash = web3.solidity_keccak(["bytes"], [group_key])
        if decrypt_group_key_hash != group_key_hash:
            print(
                f"{account_num}-The decrypted group_key_hash is incorrect: {group_key_hash}"
            )
            return

        # Get device address list
        device_addresses_tuple = group_key_management.getDeviceAddresses(
            {"from": account, "required_confs": 0}
        )
        device_addresses_list = list(device_addresses_tuple)

        # Get a list of device IP addresses
        device_ips_tuple = group_key_management.getDeviceIps(
            {"from": account, "required_confs": 0}
        )
        device_ips_list = list(device_ips_tuple)

        # Shuffle the list to increase randomness
        random.shuffle(device_addresses_list)

        # Obtain the corresponding public key and IP according to the device address,
        # and then encrypt and distribute the group key
        for device_address in device_addresses_list:
            send_thread = threading.Thread(
                target=send_group_key_data_to_device,
                args=(
                    group_key_management,
                    device_address,
                    device_ips_list,
                    account,
                    account_num,
                    group_key,
                    group_key_hash,
                    group_key_updated_time,
                    send_message_hash,
                    self_private_key,
                ),
            )
            send_thread.start()


def send_group_key_data_to_device(
    group_key_management,
    device_address,
    device_ips_list,
    account,
    account_num,
    group_key,
    group_key_hash,
    group_key_updated_time,
    send_message_hash,
    self_private_key,
):
    device_public_key_bytes = group_key_management.getDevicePublicKey(
        device_address, {"from": account, "required_confs": 0}
    )
    device_public_key = serialization.load_pem_public_key(device_public_key_bytes)
    shared_key = self_private_key.exchange(ec.ECDH(), device_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=group_key_hash,
    ).derive(shared_key)
    derived_key_base64 = base64.urlsafe_b64encode(derived_key)
    derived_key_fernet = Fernet(derived_key_base64)
    encrypted_group_key = derived_key_fernet.encrypt(group_key)
    device_ip = group_key_management.getDeviceIp(
        device_address, {"from": account, "required_confs": 0}
    )

    # Construct the data to be sent
    request_message_type = encode_defunct(send_message_hash)
    send_message_sign = web3.eth.account.sign_message(
        request_message_type, private_key=account.private_key
    )

    send_data = [
        "group key",
        SELF_CHAIN_ID,
        group_key_updated_time,
        group_key_hash,
        encrypted_group_key,
        send_message_sign,
        device_ips_list,
    ]
    send_data_bytes = pickle.dumps(send_data)

    # Send Group Key
    try:
        socket_client = socket.socket()
        socket_client.connect(("", int(device_ip)))
        socket_client.sendall(send_data_bytes)
        socket_client.close()
    except:
        pass


# Send new blockchain node information
def distribute_new_addresses(
    changed_time,
    changed_address,
    changed_address_hash,
    send_message_hash,
    account,
    account_num,
):
    group_key_management = GroupKeyManagement[-1]

    device_addresses_tuple = group_key_management.getDeviceAddresses(
        {"from": account, "required_confs": 0}
    )
    device_addresses_list = list(device_addresses_tuple)

    random.shuffle(device_addresses_list)

    for device_address in device_addresses_list:
        send_thread = threading.Thread(
            target=send_new_address_data_to_device,
            args=(
                group_key_management,
                device_address,
                account,
                account_num,
                changed_time,
                changed_address,
                changed_address_hash,
                send_message_hash,
            ),
        )
        send_thread.start()


def send_new_address_data_to_device(
    group_key_management,
    device_address,
    account,
    account_num,
    changed_time,
    changed_address,
    changed_address_hash,
    send_message_hash,
):
    device_ip = group_key_management.getDeviceIp(
        device_address, {"from": account, "required_confs": 0}
    )

    send_data_bytes = build_new_address_data(
        changed_time, changed_address, changed_address_hash, send_message_hash, account
    )

    try:
        socket_client = socket.socket()
        socket_client.connect(("", int(device_ip)))
        socket_client.sendall(send_data_bytes)
        socket_client.close()
    except:
        pass


def build_new_address_data(
    changed_time, changed_address, changed_address_hash, send_message_hash, account
):
    send_message_type = "new addresses"

    request_message_type = encode_defunct(send_message_hash)
    send_message_sign = web3.eth.account.sign_message(
        request_message_type, private_key=account.private_key
    )

    send_data = [
        send_message_type,
        SELF_CHAIN_ID,
        changed_time,
        changed_address_hash,
        changed_address,
        send_message_sign,
    ]
    send_data_bytes = pickle.dumps(send_data)

    return send_data_bytes

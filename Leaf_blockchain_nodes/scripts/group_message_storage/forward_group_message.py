# Forwarding group messages

from brownie import (
    GroupKeyManagement,
    web3,
    PublicKeyStorage,
    GroupMessageStorage,
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
import random
import socket
import datetime
import pickle
import base64
from eth_account.messages import encode_defunct
from scripts.configure_basic_parameters.addresses_and_ips import (
    get_addresses,
    get_ip_by_address,
)
from scripts.configure_basic_parameters.adjacent_chains import SELF_CHAIN_ID


# Forward group messages to the parent blockchain
def send_group_message_to_parent(
    received_timestamp,
    group_message_hash,
    received_message_sign,
    send_message_hash,
    group_message,
    account,
    account_num,
    lock,
    self_private_key,
    message_level,
):
    # Calculate some common data
    request_message_type = encode_defunct(send_message_hash)
    send_message_sign = web3.eth.account.sign_message(
        request_message_type, private_key=account.private_key
    )
    send_message_sign_hash = web3.solidity_keccak(
        ["bytes"], [send_message_sign.signature]
    )
    request_message_type = encode_defunct(send_message_sign_hash)

    group_message_storage = GroupMessageStorage[-1]
    public_key_storage = PublicKeyStorage[-1]

    # Select the address of the parent blockchain
    hash_int = int.from_bytes(send_message_hash, byteorder="big")
    parent_addresses = get_addresses("parent")
    parent_addresses_length = len(parent_addresses)
    require_num = int((parent_addresses_length - 1) / 3 + 1)
    start_index = hash_int % parent_addresses_length
    choose_addresses = []
    for i in range(require_num):
        choose_addresses.append(
            parent_addresses[(start_index + i) % parent_addresses_length]
        )

    random.shuffle(choose_addresses)

    # Forward group messages to the parent blockchain
    for choose_address in choose_addresses:
        send_data_to_parent(
            received_timestamp,
            group_message_hash,
            received_message_sign,
            group_message,
            account,
            send_message_sign,
            request_message_type,
            group_message_storage,
            public_key_storage,
            choose_address,
            account_num,
            lock,
            self_private_key,
            message_level,
        )


def send_data_to_parent(
    received_timestamp,
    group_message_hash,
    received_message_sign,
    group_message,
    account,
    send_message_sign,
    request_message_type,
    group_message_storage,
    public_key_storage,
    choose_address,
    account_num,
    lock,
    self_private_key,
    message_level,
):
    choose_address_ip = get_ip_by_address(choose_address, "parent")

    # Generate a temporary session key and encrypt
    parent_public_key_bytes = public_key_storage.getParentPublicKey(
        choose_address, {"from": account, "required_confs": 0}
    )
    parent_public_key = serialization.load_pem_public_key(parent_public_key_bytes)
    shared_key = self_private_key.exchange(ec.ECDH(), parent_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=group_message_hash,
    ).derive(shared_key)
    derived_key_base64 = base64.urlsafe_b64encode(derived_key)
    derived_key_fernet = Fernet(derived_key_base64)

    # Encrypted group messages
    encrypted_group_message = derived_key_fernet.encrypt(group_message)

    # Construct the format of the data to be sent
    send_data = [
        "group message",
        SELF_CHAIN_ID,
        received_timestamp,
        group_message_hash,
        encrypted_group_message,
        send_message_sign,
        message_level,
    ]
    send_data_bytes = pickle.dumps(send_data)

    handle_result = False
    result_content = b""
    try:
        # Send the group message to the selected parent blockchain node
        socket_client = socket.socket()
        socket_client.connect(("", int(choose_address_ip)))
        socket_client.sendall(send_data_bytes)

        # Receive the reply from the parent blockchain node,
        # determine whether to confirm or reject the signature,
        # and make corresponding processing
        received_replied_data_bytes = socket_client.recv(8192)
        socket_client.close()
        received_repiled_data = pickle.loads(received_replied_data_bytes)
    except Exception as e:
        received_replied_data_bytes = b""
        result_content = f"An error occurred connecting to choose_address: {e}".encode()
    else:
        # If the connection is normal, process the data replied by the parent blockchain node
        received_handle_result = received_repiled_data[0]
        received_result_content = received_repiled_data[1]

        if received_handle_result.decode() == "failure":
            handle_result = False
            result_content = f"send_group_message_to_parent received failure result: {received_result_content.decode()}".encode()
        else:
            # Verify that the signature is correct
            signer = web3.eth.account.recover_message(
                request_message_type, signature=received_result_content.signature
            )
            if signer != choose_address:
                handle_result = False
                result_content = (
                    "send_group_message_to_parent received wrong contersign".encode()
                )
            else:
                handle_result = True
                result_content = received_result_content

    if handle_result is not True:
        if result_content.decode().find("The message has been processed") == -1:
            log_datetime = datetime.datetime.today().strftime("%Y%m%d")
            file_name = f"./runtimedata/exceptions/account{str(account_num).zfill(2)}/{log_datetime}_forward_group_message.txt"
            with open(file_name, "a") as f:
                time_now = int(datetime.datetime.today().timestamp())
                f.write(str(time_now))
                f.write("\n")
                f.write(send_data_bytes.hex())
                f.write("\n")
                f.write(choose_address_ip)
                f.write("\n")
                f.write(received_replied_data_bytes.hex())
                f.write("\n")
                f.write(result_content.decode())
                f.write("\n")
                f.flush()
    else:
        try:
            with lock:
                # nonce = web3.eth.get_transaction_count(account.address)
                group_message_storage.storeGroupMessageHashCountersign(
                    message_level,
                    received_timestamp,
                    group_message_hash,
                    received_message_sign,
                    send_message_sign,
                    result_content,
                    {"from": account, "required_confs": 0},
                )
        except Exception as e:
            if str(e).find("Countersigner already exists") == -1:
                print(
                    f"{int(datetime.datetime.today().timestamp())} GroupMessageStorage's storeGroupMessageHashCountersign error: {e}"
                )


# Forward group messages to device groups
def send_group_message_to_devices(
    received_timestamp,
    signer,
    self_private_key,
    group_message,
    group_message_hash,
    account,
    account_num,
    message_level,
):
    send_message_hash = web3.solidity_keccak(
        ["uint256", "uint256", "bytes32"],
        [message_level, received_timestamp, group_message_hash],
    )

    group_key_management = GroupKeyManagement[-1]
    latest_group_key_hashs = group_key_management.getLatestGroupKeyHashs(
        {"from": account}
    )
    generator_public_key_bytes, encrypted_group_key = (
        group_key_management.getEncryptedGroupKey(
            latest_group_key_hashs[0],
            account.address,
            {"from": account, "required_confs": 0},
        )
    )
    generator_public_key = serialization.load_pem_public_key(generator_public_key_bytes)
    shared_key = self_private_key.exchange(ec.ECDH(), generator_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=latest_group_key_hashs[0],
    ).derive(shared_key)
    derived_key_base64 = base64.urlsafe_b64encode(derived_key)
    derived_key_fernet = Fernet(derived_key_base64)
    try:
        group_key = derived_key_fernet.decrypt(encrypted_group_key)
    except:
        print(
            f"{account_num}-The decrypted group_key is incorrect: {latest_group_key_hashs[0]}"
        )
    else:
        fernet_group_key = Fernet(group_key)
        encrypted_group_message = fernet_group_key.encrypt(group_message)
        request_message_type = encode_defunct(send_message_hash)
        send_message_sign = web3.eth.account.sign_message(
            request_message_type, private_key=account.private_key
        )

        send_data = [
            "group message",
            SELF_CHAIN_ID,
            received_timestamp,
            group_message_hash,
            encrypted_group_message,
            send_message_sign,
            message_level,
        ]
        send_data_bytes = pickle.dumps(send_data)

        # Get device address list
        device_addresses_tuple = group_key_management.getDeviceAddresses(
            {"from": account, "required_confs": 0}
        )
        device_addresses_list = list(device_addresses_tuple)

        # If the message source is a device, remove the device from the receiving list
        if signer in device_addresses_list:
            device_addresses_list.remove(signer)

        random.shuffle(device_addresses_list)

        # Get the corresponding IP according to the device address,
        # and then send a group message
        for device_address in device_addresses_list:
            # Send a group message
            send_data_to_device(
                group_key_management,
                device_address,
                account,
                account_num,
                send_data_bytes,
                group_message,
            )


def send_data_to_device(
    group_key_management,
    device_address,
    account,
    account_num,
    send_data_bytes,
    group_message,
):
    device_ip = group_key_management.getDeviceIp(
        device_address, {"from": account, "required_confs": 0}
    )
    try:
        socket_client = socket.socket()
        socket_client.connect(("", int(device_ip)))
        socket_client.sendall(send_data_bytes)
        socket_client.close()
    except:
        pass

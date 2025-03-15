# Processing received messages

from brownie import (
    web3,
    GroupKeyManagement,
    config,
    GroupMessageStorage,
    PublicKeyStorage,
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
import datetime
import time
import pickle
import threading
import base64
from eth_account.messages import encode_defunct
from scripts.configure_basic_parameters.addresses_and_ips import (
    get_addresses,
    address_exists,
)
from scripts.group_key_management.store import store_group_key
from scripts.group_message_storage.forward_group_message import (
    send_group_message_to_parent,
    send_group_message_to_devices,
)
from scripts.configure_basic_parameters.sec_key_utils import (
    get_self_chain_public_keys,
    my_load_private_key,
)
from scripts.message_rocord_storage.send_request_to_device import send_request_to_device


# Handling device join requests
def handle_join_group_message(received_data, account, account_num, lock):
    # Extract individual data items from the received data
    received_timestamp = received_data[1]
    device_cert = received_data[2]
    received_message_sign = received_data[3]

    # Verify that the timestamp meets the requirements
    now_timestamp = int(datetime.datetime.today().timestamp())
    if now_timestamp - received_timestamp > config["default_timeout"]:
        return

    # Intermediate data required for calculation verification
    cert_hash = web3.solidity_keccak(
        [
            "uint256",
            "string",
            "bytes",
            "address",
            "uint256",
            "uint256",
            "uint256",
        ],
        [
            device_cert[0],
            device_cert[1],
            device_cert[2],
            device_cert[3],
            device_cert[4],
            device_cert[5],
            device_cert[6],
        ],
    )
    format_cert_sign = (
        web3.to_hex(device_cert[8].messageHash),
        to_32byte_hex(device_cert[8].r),
        to_32byte_hex(device_cert[8].s),
        device_cert[8].v,
    )
    cert_sign_hash = web3.solidity_keccak(
        ["bytes32", "bytes32", "bytes32", "uint8", "bytes"],
        [
            format_cert_sign[0],
            format_cert_sign[1],
            format_cert_sign[2],
            format_cert_sign[3],
            device_cert[8][4],
        ],
    )
    cert_message_hash = web3.solidity_keccak(
        [
            "uint256",
            "string",
            "bytes",
            "address",
            "uint256",
            "uint256",
            "uint256",
            "bytes32",
            "bytes32",
        ],
        [
            device_cert[0],
            device_cert[1],
            device_cert[2],
            device_cert[3],
            device_cert[4],
            device_cert[5],
            device_cert[6],
            device_cert[7],
            cert_sign_hash,
        ],
    )
    received_message_hash = web3.solidity_keccak(
        ["uint256", "bytes32"],
        [received_timestamp, cert_message_hash],
    )

    # Calculate whether its own address is in the hash table
    hash_int = int.from_bytes(received_message_hash, byteorder="big")
    self_addresses = get_addresses()
    self_addresses_length = len(self_addresses)
    require_num = int((self_addresses_length - 1) / 3 + 1)
    start_index = hash_int % self_addresses_length
    choose_addresses = []
    for i in range(require_num):
        choose_addresses.append(
            self_addresses[(start_index + i) % self_addresses_length]
        )
    if account.address not in choose_addresses:
        return

    # Verify that the certificate hash is correct
    if cert_hash != device_cert[7]:
        return

    # Verify that the certificate signature is correct
    request_message_type = encode_defunct(cert_hash)
    signer = web3.eth.account.recover_message(
        request_message_type, signature=device_cert[8].signature
    )
    if address_exists(signer, "ca") is not True:
        return

    # Verify that the certificate validity period is correct
    if now_timestamp < device_cert[5] or now_timestamp > device_cert[6]:
        return

    # Verify whether the signature of the request message is correct,
    # that is, determine whether it has joined the group
    request_message_type = encode_defunct(received_message_hash)
    signer = web3.eth.account.recover_message(
        request_message_type, signature=received_message_sign.signature
    )
    if signer != device_cert[3]:
        return

    group_key_management = GroupKeyManagement[-1]
    address_exists_result = group_key_management.checkDeviceAddress(
        signer, {"from": account, "required_confs": 0}
    )
    if address_exists_result:
        return

    print(f"{datetime.datetime.now().timestamp()}开始生成群组密钥")

    # Generate a group key and a hash of the group key
    group_key_hash_is_exist = True
    while group_key_hash_is_exist is True:
        group_key = Fernet.generate_key()
        group_key_hash = web3.solidity_keccak(["bytes"], [group_key])
        # Determine whether the group key has been used, and if so, regenerate the group key
        group_key_hash_is_exist = group_key_management.groupKeyHashIsExist(
            group_key_hash, {"from": account, "required_confs": 0}
        )

    # Encrypt the group key using the public key of each blockchain node
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

    # Store the ciphertext and hash of the group key in the blockchain
    store_group_key(
        received_data,
        group_key_hash,
        self_addresses,
        encrypted_group_keys,
        account,
        lock,
        hash_int,
    )

    if hash_int % config["trigger_threshold"] < config["triggering_conditions"]:
        time.sleep(config["request_delay"])
        send_request_to_device(
            received_message_hash,
            received_timestamp,
            hash_int,
            require_num,
            account,
            account_num,
            lock,
        )


def to_32byte_hex(val):
    return web3.to_hex(web3.to_bytes(val).rjust(32, b"\0"))


# Handling device leave requests
def handle_leave_group_message(received_data, account, account_num, lock):
    received_timestamp = received_data[1]
    received_message_sign = received_data[2]

    now_timestamp = int(datetime.datetime.today().timestamp())
    if now_timestamp - received_timestamp > config["default_timeout"]:
        return

    received_message_hash = web3.solidity_keccak(["uint256"], [received_timestamp])

    hash_int = int.from_bytes(received_message_hash, byteorder="big")
    self_addresses = get_addresses()
    self_addresses_length = len(self_addresses)
    require_num = int((self_addresses_length - 1) / 3 + 1)
    start_index = hash_int % self_addresses_length
    choose_addresses = []
    for i in range(require_num):
        choose_addresses.append(
            self_addresses[(start_index + i) % self_addresses_length]
        )
    if account.address not in choose_addresses:
        return

    # Check if the device is still in the group and verify the signature
    request_message_type = encode_defunct(received_message_hash)
    signer = web3.eth.account.recover_message(
        request_message_type, signature=received_message_sign.signature
    )
    group_key_management = GroupKeyManagement[-1]
    address_exists_result = group_key_management.checkDeviceAddress(
        signer, {"from": account, "required_confs": 0}
    )
    if address_exists_result is not True:
        return

    print(f"{datetime.datetime.now().timestamp()}开始生成群组密钥")

    group_key_hash_is_exist = True
    while group_key_hash_is_exist is True:
        group_key = Fernet.generate_key()
        group_key_hash = web3.solidity_keccak(["bytes"], [group_key])
        group_key_hash_is_exist = group_key_management.groupKeyHashIsExist(
            group_key_hash, {"from": account, "required_confs": 0}
        )

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

    print(f"生成了组密钥哈希: {group_key_hash}")

    store_group_key(
        received_data,
        group_key_hash,
        self_addresses,
        encrypted_group_keys,
        account,
        lock,
        hash_int,
    )

    if hash_int % config["trigger_threshold"] < config["triggering_conditions"]:
        time.sleep(config["request_delay"])
        send_request_to_device(
            received_message_hash,
            received_timestamp,
            hash_int,
            require_num,
            account,
            account_num,
            lock,
        )


# Process group messages from the parent blockchain
def handle_parent_group_message(
    sender_socket,
    sender_address,
    received_data,
    account,
    account_num,
    message_buffer,
    lock,
):
    received_timestamp = received_data[2]

    (
        handle_result,
        result_content,
        received_message_hash,
        hash_int,
        require_num,
        signer,
        self_private_key,
        group_message,
    ) = verify_parent_group_message(received_data, account, account_num, message_buffer)

    # Constructing the data format of the reply
    send_data = [
        handle_result,
        result_content,
    ]
    send_data_bytes = pickle.dumps(send_data)

    # Reply to a message
    try:
        sender_socket.sendall(send_data_bytes)
        sender_socket.close()
    except Exception as e:
        handle_result = "failure".encode()
        result_content = f"An error occurred connecting to sender: {e}".encode()

    if handle_result.decode() == "failure":
        if result_content.decode().find("The message has been processed") == -1:
            log_datetime = datetime.datetime.today().strftime("%Y%m%d")
            file_name = f"./runtimedata/exceptions/account{str(account_num).zfill(2)}/{log_datetime}_handle_received_message.txt"
            with open(file_name, "a") as f:
                time_now = int(datetime.datetime.today().timestamp())
                f.write(str(time_now))
                f.write("\n")
                f.write((pickle.dumps(sender_address)).hex())
                f.write("\n")
                f.write((pickle.dumps(received_data)).hex())
                f.write("\n")
                f.write(result_content.decode())
                f.write("\n")
                f.flush()
    else:
        # Storing group messages in the contract
        group_massage_storage = GroupMessageStorage[-1]
        received_message_sign = received_data[5]
        try:
            with lock:
                group_massage_storage.storeGroupMessageHashFromParent(
                    received_data[6],
                    received_timestamp,
                    received_data[3],
                    received_message_sign,
                    {"from": account, "required_confs": 0},
                )
        except Exception as e:
            if str(e).find("The number of forwarder are sufficient") == -1:
                print(
                    f"{int(datetime.datetime.today().timestamp())} GroupMessageStorage's storeGroupMessageHashFromParent error: {e}"
                )

        # Send group messages to devices in the group
        send_group_message_to_devices(
            received_timestamp,
            signer,
            self_private_key,
            group_message,
            received_data[3],
            account,
            account_num,
            received_data[6],
        )

        if hash_int % config["trigger_threshold"] < config["triggering_conditions"]:
            time.sleep(config["request_delay"])
            send_request_to_device(
                received_message_hash,
                received_data[2],
                hash_int,
                require_num,
                account,
                account_num,
                lock,
            )


# Verify group messages from blockchain
def verify_parent_group_message(received_data, account, account_num, message_buffer):
    # Extracting information
    received_timestamp = received_data[2]
    received_hash = received_data[3]
    received_message = received_data[4]
    received_message_sign = received_data[5]
    received_message_level = received_data[6]

    # Check that the message hierarchy is correct
    if received_message_level >= config["blockchain_level"]:
        handle_result = "failure".encode()
        result_content = "There is incorrect message levle".encode()
        return handle_result, result_content, None, None, None, None, None, None

    now_timestamp = int(datetime.datetime.today().timestamp())
    if now_timestamp - received_timestamp > config["default_timeout"]:
        handle_result = "failure".encode()
        result_content = "There is incorrect timestamp".encode()
        return handle_result, result_content, None, None, None, None, None, None, None

    # Check if the message has been received
    message_info = (received_timestamp, received_hash)
    if message_buffer.add_message(message_info) is not True:
        handle_result = "failure".encode()
        result_content = "The message has been processed".encode()
        return handle_result, result_content, None, None, None, None, None, None

    received_message_hash = web3.solidity_keccak(
        ["uint256", "uint256", "bytes32"],
        [received_message_level, received_timestamp, received_hash],
    )

    hash_int = int.from_bytes(received_message_hash, byteorder="big")
    self_addresses = get_addresses()
    self_addresses_length = len(self_addresses)
    require_num = int((self_addresses_length - 1) / 3 + 1)
    start_index = hash_int % self_addresses_length
    choose_addresses = []
    for i in range(require_num):
        choose_addresses.append(
            self_addresses[(start_index + i) % self_addresses_length]
        )
    if account.address not in choose_addresses:
        handle_result = "failure".encode()
        result_content = "The account.address not in hash table".encode()
        return (
            handle_result,
            result_content,
            received_message_hash,
            hash_int,
            require_num,
            None,
            None,
            None,
        )

    # Verify that the signature is correct and that the signer is in the hash table
    request_message_type = encode_defunct(received_message_hash)
    signer = web3.eth.account.recover_message(
        request_message_type, signature=received_message_sign.signature
    )
    parent_addresses = get_addresses("parent")
    parent_addresses_length = len(parent_addresses)
    require_num = int((parent_addresses_length - 1) / 3 + 1)
    start_index = hash_int % parent_addresses_length
    choose_addresses = []
    for i in range(require_num):
        choose_addresses.append(
            parent_addresses[(start_index + i) % parent_addresses_length]
        )
    if signer not in choose_addresses:
        handle_result = "failure".encode()
        result_content = "There is incorrect message_sign".encode()
        return (
            handle_result,
            result_content,
            received_message_hash,
            hash_int,
            require_num,
            signer,
            None,
            None,
        )

    # Decrypting group messages
    account_num_str = str(account_num).zfill(2)
    self_private_key = my_load_private_key(account_num_str)
    public_key_storage = PublicKeyStorage[-1]
    signer_public_key_bytes = public_key_storage.getParentPublicKey(
        signer, {"from": account, "required_confs": 0}
    )
    signer_public_key = serialization.load_pem_public_key(signer_public_key_bytes)
    shared_key = self_private_key.exchange(ec.ECDH(), signer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=received_hash,
    ).derive(shared_key)
    derived_key_base64 = base64.urlsafe_b64encode(derived_key)
    derived_key_fernet = Fernet(derived_key_base64)

    try:
        group_message = derived_key_fernet.decrypt(received_message)
    except:
        handle_result = "failure".encode()
        result_content = "Failed to decrypt received_message correctly".encode()
        return (
            handle_result,
            result_content,
            received_message_hash,
            hash_int,
            require_num,
            signer,
            self_private_key,
            None,
        )

    # Verify that the decrypted group message is correct
    group_message_hash = web3.solidity_keccak(["bytes"], [group_message])
    if group_message_hash != received_hash:
        handle_result = "failure".encode()
        result_content = "There is incorrect group_message_hash".encode()
        return (
            handle_result,
            result_content,
            received_message_hash,
            hash_int,
            require_num,
            signer,
            self_private_key,
            group_message,
        )

    # Sign the hash of the timestamp and message hash
    handle_result = "success".encode()
    received_message_sign_hash = web3.solidity_keccak(
        ["bytes"], [received_message_sign.signature]
    )
    request_message_type = encode_defunct(received_message_sign_hash)
    received_message_countersign = web3.eth.account.sign_message(
        request_message_type, private_key=account.private_key
    )
    result_content = received_message_countersign

    return (
        handle_result,
        result_content,
        received_message_hash,
        hash_int,
        require_num,
        signer,
        self_private_key,
        group_message,
    )


# Handle group messages from devices
def handle_devices_group_message(
    sender_socket, received_data, account, account_num, lock
):
    try:
        sender_socket.close()
    except Exception as e:
        pass

    received_timestamp = received_data[2]
    received_hash = received_data[3]
    received_message = received_data[4]
    received_message_sign = received_data[5]
    received_message_level = received_data[6]

    if received_message_level >= config["blockchain_level"]:
        return

    now_timestamp = int(datetime.datetime.today().timestamp())
    if now_timestamp - received_timestamp > config["default_timeout"]:
        return

    received_message_hash = web3.solidity_keccak(
        ["uint256", "uint256", "bytes32"],
        [received_message_level, received_timestamp, received_hash],
    )

    hash_int = int.from_bytes(received_message_hash, byteorder="big")
    self_addresses = get_addresses()
    self_addresses_length = len(self_addresses)
    require_num = int((self_addresses_length - 1) / 3 + 1)
    start_index = hash_int % self_addresses_length
    choose_addresses = []
    for i in range(require_num):
        choose_addresses.append(
            self_addresses[(start_index + i) % self_addresses_length]
        )
    if account.address not in choose_addresses:
        return

    request_message_type = encode_defunct(received_message_hash)
    signer = web3.eth.account.recover_message(
        request_message_type, signature=received_message_sign.signature
    )
    group_key_management = GroupKeyManagement[-1]
    address_exists_result = group_key_management.checkDeviceAddress(
        signer, {"from": account, "required_confs": 0}
    )
    if address_exists_result is not True:
        return

    latest_group_key_hashs = group_key_management.getLatestGroupKeyHashs(
        {"from": account, "required_confs": 0}
    )
    decryption_successful = False
    account_num_str = str(account_num).zfill(2)
    self_private_key = my_load_private_key(account_num_str)

    for group_key_hash in latest_group_key_hashs:
        generator_public_key_bytes, encrypted_group_key = (
            group_key_management.getEncryptedGroupKey(
                group_key_hash, account.address, {"from": account, "required_confs": 0}
            )
        )
        generator_public_key = serialization.load_pem_public_key(
            generator_public_key_bytes
        )
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
            print(
                f"{account_num}-The decrypted group_key is incorrect: {group_key_hash}"
            )
            pass
        else:
            try:
                fernet_group_key = Fernet(group_key)
            except:
                pass
            else:
                try:
                    group_message = fernet_group_key.decrypt(received_message)
                except:
                    pass
                else:
                    # Verify that the decrypted group message is correct
                    group_message_hash = web3.solidity_keccak(
                        ["bytes"], [group_message]
                    )
                    if group_message_hash == received_hash:
                        decryption_successful = True
                        break

    if decryption_successful is not True:
        return

    # Send group message to parent blockchain
    send_group_message_to_parent(
        received_timestamp,
        received_hash,
        received_message_sign,
        received_message_hash,
        group_message,
        account,
        account_num,
        lock,
        self_private_key,
        received_message_level,
    )

    if hash_int % config["trigger_threshold"] < config["triggering_conditions"]:
        time.sleep(config["request_delay"])
        send_request_to_device(
            received_message_hash,
            received_timestamp,
            hash_int,
            require_num,
            account,
            account_num,
            lock,
        )

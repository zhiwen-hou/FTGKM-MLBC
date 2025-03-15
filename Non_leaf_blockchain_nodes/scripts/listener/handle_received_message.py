from brownie import web3, config, PublicKeyStorage
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import pickle
import datetime
import base64
from eth_account.messages import encode_defunct
from scripts.configure_basic_parameters.addresses_and_ips import (
    get_addresses_length,
    address_exists,
    get_addresses,
)
from scripts.configure_basic_parameters.adjacent_chains import (
    chian_id_exists,
    get_adjacent_chain_name_by_id,
)
from scripts.group_message_storage.forward_group_message import (
    send_group_message_to_adjacent_chains,
)
from scripts.configure_basic_parameters.sec_key_utils import my_load_private_key


def handle_group_message_message(
    sender_socket,
    sender_address,
    received_data,
    account,
    account_num,
    message_buffer,
    lock,
):
    (
        handle_result,
        result_content,
        self_private_key,
        group_message,
        received_message_hash,
    ) = verify_group_message_message(
        received_data, account, account_num, message_buffer, sender_address
    )

    send_data = [
        handle_result,
        result_content,
    ]
    send_data_bytes = pickle.dumps(send_data)

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
        # Send group messages to other adjacent blockchains
        send_group_message_to_adjacent_chains(
            received_data[1],
            received_data[2],
            received_data[3],
            received_data[5],
            received_message_hash,
            group_message,
            account,
            account_num,
            lock,
            self_private_key,
            received_data[6],
        )


def verify_group_message_message(
    received_data, account, account_num, message_buffer, sender_address
):
    sender_chain_id = received_data[1]
    received_timestamp = received_data[2]
    received_hash = received_data[3]
    received_message = received_data[4]
    received_message_sign = received_data[5]
    received_message_level = received_data[6]

    if received_message_level > config["blockchain_level"]:
        return

    # Check if the given blockchain ID exists
    if chian_id_exists(sender_chain_id) is not True:
        handle_result = "failure".encode()
        result_content = "There is incorrect chain_id".encode()
        return handle_result, result_content, None, None, None

    now_timestamp = int(datetime.datetime.today().timestamp())
    if now_timestamp - received_timestamp > config["default_timeout"]:
        handle_result = "failure".encode()
        result_content = "There is incorrect timestamp".encode()
        return handle_result, result_content, None, None, None

    message_info = (received_timestamp, received_hash)
    if message_buffer.add_message(message_info) is not True:
        handle_result = "failure".encode()
        result_content = "The message has been processed".encode()
        return handle_result, result_content, None, None, None

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
        return handle_result, result_content, None, None, received_message_hash

    request_message_type = encode_defunct(received_message_hash)
    signer = web3.eth.account.recover_message(
        request_message_type, signature=received_message_sign.signature
    )
    sender_chain_name = get_adjacent_chain_name_by_id(sender_chain_id)
    sender_addresses = get_addresses(sender_chain_name)
    sender_addresses_length = len(sender_addresses)
    require_num = int((sender_addresses_length - 1) / 3 + 1)
    start_index = hash_int % sender_addresses_length
    choose_addresses = []
    for i in range(require_num):
        choose_addresses.append(
            sender_addresses[(start_index + i) % sender_addresses_length]
        )
    if signer not in choose_addresses:
        handle_result = "failure".encode()
        result_content = "There is incorrect message_sign".encode()
        return handle_result, result_content, None, None, received_message_hash

    account_num_str = str(account_num).zfill(2)
    self_private_key = my_load_private_key(account_num_str)
    public_key_storage = PublicKeyStorage[-1]
    signer_public_key_bytes = public_key_storage.getSonPublicKey(
        sender_chain_id, signer, {"from": account, "required_confs": 0}
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
        return handle_result, result_content, None, received_message_hash

    group_message_hash = web3.solidity_keccak(["bytes"], [group_message])
    if group_message_hash != received_hash:
        handle_result = "failure".encode()
        result_content = "There is incorrect group_message_hash".encode()
        return (
            handle_result,
            result_content,
            self_private_key,
            group_message,
            received_message_hash,
        )

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
        self_private_key,
        group_message,
        received_message_hash,
    )

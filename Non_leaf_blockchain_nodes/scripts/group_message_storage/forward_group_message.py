from brownie import web3, PublicKeyStorage, GroupMessageStorage
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
import random
import socket
import datetime
import pickle
import threading
import traceback
import base64
from eth_account.messages import encode_defunct
from scripts.configure_basic_parameters.addresses_and_ips import (
    get_addresses,
    get_ip_by_address,
)
from scripts.configure_basic_parameters.adjacent_chains import (
    SELF_CHAIN_ID,
    get_adjacent_chain_ids,
    get_adjacent_chain_name_by_id,
)


# Send group messages to other adjacent blockchains
def send_group_message_to_adjacent_chains(
    sender_chain_id,
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
    adjacent_chain_ids = get_adjacent_chain_ids()
    # Exclude message source blockchain
    adjacent_chain_ids.remove(sender_chain_id)

    for adjacent_chain_id in adjacent_chain_ids:
        # Sent to all adjacent blockchains except the source blockchain
        send_thread = threading.Thread(
            target=send_group_message_to_adjacent_chain,
            args=(
                adjacent_chain_id,
                sender_chain_id,
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
            ),
        )
        send_thread.start()


def send_group_message_to_adjacent_chain(
    adjacent_chain_id,
    sender_chain_id,
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
    request_message_type = encode_defunct(send_message_hash)
    send_message_sign = web3.eth.account.sign_message(
        request_message_type, private_key=account.private_key
    )
    send_message_sign_hash = web3.solidity_keccak(
        ["bytes"], [send_message_sign.signature]
    )
    request_message_type = encode_defunct(send_message_sign_hash)

    group_massage_storage = GroupMessageStorage[-1]
    public_key_storage = PublicKeyStorage[-1]

    hash_int = int.from_bytes(send_message_hash, byteorder="big")
    adjacent_chain_name = get_adjacent_chain_name_by_id(adjacent_chain_id)
    adjacent_chain_addresses = get_addresses(adjacent_chain_name)
    adjacent_chain_addresses_length = len(adjacent_chain_addresses)
    require_num = int((adjacent_chain_addresses_length - 1) / 3 + 1)
    start_index = hash_int % adjacent_chain_addresses_length
    choose_addresses = []
    for i in range(require_num):
        choose_addresses.append(
            adjacent_chain_addresses[
                (start_index + i) % adjacent_chain_addresses_length
            ]
        )

    random.shuffle(choose_addresses)

    for choose_address in choose_addresses:
        send_thread = threading.Thread(
            target=send_data_to_adjacent_chain,
            args=(
                adjacent_chain_id,
                sender_chain_id,
                received_timestamp,
                group_message_hash,
                received_message_sign,
                group_message,
                account,
                send_message_sign,
                request_message_type,
                group_massage_storage,
                public_key_storage,
                adjacent_chain_name,
                choose_address,
                account_num,
                lock,
                self_private_key,
                message_level,
            ),
        )
        send_thread.start()


def send_data_to_adjacent_chain(
    adjacent_chain_id,
    sender_chain_id,
    received_timestamp,
    group_message_hash,
    received_message_sign,
    group_message,
    account,
    send_message_sign,
    request_message_type,
    group_massage_storage,
    public_key_storage,
    adjacent_chain_name,
    choose_address,
    account_num,
    lock,
    self_private_key,
    message_level,
):
    choose_address_ip = get_ip_by_address(choose_address, adjacent_chain_name)

    # Generate a temporary session key and encrypt
    adjacent_public_key_bytes = public_key_storage.getSonPublicKey(
        adjacent_chain_id, choose_address, {"from": account, "required_confs": 0}
    )
    adjacent_public_key = serialization.load_pem_public_key(adjacent_public_key_bytes)
    shared_key = self_private_key.exchange(ec.ECDH(), adjacent_public_key)
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
        # Send group messages to selected neighboring blockchain nodes
        socket_client = socket.socket()
        socket_client.connect(("", int(choose_address_ip)))
        socket_client.sendall(send_data_bytes)

        # Receive the reply from the blockchain node, determine whether
        # to confirm or reject the signature, and make corresponding processing
        received_replied_data_bytes = socket_client.recv(8192)
        socket_client.close()
        received_repiled_data = pickle.loads(received_replied_data_bytes)
    except Exception as e:
        received_replied_data_bytes = b""
        result_content = f"An error occurred connecting to choose_address: {e}".encode()
    else:
        received_handle_result = received_repiled_data[0]
        received_result_content = received_repiled_data[1]

        if received_handle_result.decode() == "failure":
            handle_result = False
            result_content = f"send_group_message_to_parent received failure result: {received_result_content.decode()}".encode()
        else:
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
                group_massage_storage.storeGroupMessageHashCountersign(
                    message_level,
                    received_timestamp,
                    group_message_hash,
                    sender_chain_id,
                    received_message_sign,
                    send_message_sign,
                    adjacent_chain_id,
                    result_content,
                    {"from": account, "required_confs": 0},
                )
        except Exception as e:
            if str(e).find("Countersigner already exists") == -1:
                print(
                    f"{account_num}: {int(datetime.datetime.today().timestamp())} GroupMessageStorage's error: {e}"
                )
                traceback.print_exc()

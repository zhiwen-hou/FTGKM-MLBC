# Sending data

from brownie import web3
from cryptography.fernet import Fernet
import threading
import socket
import datetime
import pickle
import random
from eth_account.messages import encode_defunct
from scripts.leaf_blockchain import get_addresses, get_ip_by_address, LEAF_CHAIN_LEVEL


def just_send_data(choose_address_ip, send_data_bytes):
    try:
        socket_client = socket.socket()
        socket_client.connect(("", int(choose_address_ip)))
        socket_client.sendall(send_data_bytes)
        socket_client.close()
    except Exception as e:
        pass


# Send a group message
def send_group_message(
    device, choose_chain_id, message_type, group_key, choose_chain_addresses, group_ips
):
    random_num = random.random()
    if random_num < 0.5:
        message_level = 2
    else:
        message_level = 1

    if message_level == 2:
        pass
    else:
        send_group_message_to_chain(
            device,
            choose_chain_id,
            message_type,
            group_key,
            choose_chain_addresses,
            message_level,
        )
    pass


# Send a message within a subgroup
def send_group_message_to_sub_group(device, group_key, group_ips, message_level):
    timestamp = int(datetime.datetime.today().timestamp())

    group_message_str = f"Device{str(device[1][0]).zfill(3)}-{str(timestamp)}: this is a test group message"
    group_message = group_message_str.encode()

    group_message_hash = web3.solidity_keccak(["bytes"], [group_message])

    send_message_hash = web3.solidity_keccak(
        ["uint256", "uint256", "bytes32"],
        [message_level, timestamp, group_message_hash],
    )

    encrypted_group_message = group_key.encrypt(group_message)

    request_message_type = encode_defunct(send_message_hash)
    send_message_sign = web3.eth.account.sign_message(
        request_message_type, private_key=device[0]
    )

    send_data = [
        "group message",
        device[1][0],
        timestamp,
        group_message_hash,
        encrypted_group_message,
        send_message_sign,
        message_level,
    ]

    send_data_bytes = pickle.dumps(send_data)

    random_group_ips = group_ips.copy()
    random.shuffle(random_group_ips)
    thread_list = []
    for random_group_ip in random_group_ips:
        send_thread = threading.Thread(
            target=just_send_data,
            args=(random_group_ip, send_data_bytes),
        )
        thread_list.append(send_thread)

    for send_thread in thread_list:
        send_thread.start()

    for send_thread in thread_list:
        send_thread.join()


# Sending messages to the blockchain
def send_group_message_to_chain(
    device,
    choose_chain_id,
    message_type,
    group_key,
    choose_chain_addresses,
    message_level,
):
    # Construct the data to be sent and calculate the integer corresponding to the message hash
    send_data_bytes, hash_int, group_message_str = build_group_message(
        device, message_type, group_key, message_level
    )

    # Calculate the amount you need to send
    choose_addresses_length = len(choose_chain_addresses)
    require_num = int((choose_addresses_length - 1) / 3 + 1)

    # Calculate the starting coordinates
    start_index = hash_int % choose_addresses_length
    # Select an address from the address collection
    choose_addresses = []
    for i in range(require_num):
        choose_addresses.append(
            choose_chain_addresses[(start_index + i) % choose_addresses_length]
        )

    random.shuffle(choose_addresses)
    thread_list = []
    for choose_address in choose_addresses:
        choose_address_ip = get_ip_by_address(choose_address, choose_chain_id)
        send_thread = threading.Thread(
            target=just_send_data,
            args=(choose_address_ip, send_data_bytes),
        )
        thread_list.append(send_thread)

    for send_thread in thread_list:
        send_thread.start()

    for send_thread in thread_list:
        send_thread.join()


# Constructing the format of the message to be sent
def build_group_message(device, message_type, group_key, message_level):
    timestamp = int(datetime.datetime.today().timestamp())

    group_message_str = f"Device{str(device[1][0]).zfill(3)}-{str(timestamp)}: this is a test group message"
    group_message = group_message_str.encode()

    group_message_hash = web3.solidity_keccak(["bytes"], [group_message])

    send_message_hash = web3.solidity_keccak(
        ["uint256", "uint256", "bytes32"],
        [message_level, timestamp, group_message_hash],
    )

    encrypted_group_message = group_key.encrypt(group_message)

    request_message_type = encode_defunct(send_message_hash)
    send_message_sign = web3.eth.account.sign_message(
        request_message_type, private_key=device[0]
    )

    send_data = [
        message_type,
        device[1][0],
        timestamp,
        group_message_hash,
        encrypted_group_message,
        send_message_sign,
        message_level,
    ]

    send_data_bytes = pickle.dumps(send_data)

    hash_int = int.from_bytes(send_message_hash, byteorder="big")

    return send_data_bytes, hash_int, group_message_str


# Send join/leave requests
def send_request_message(device, choose_chain_id, message_type, choose_chain_addresses):
    if message_type == "join group":
        send_data_bytes, hash_int = build_join_message(device, message_type)
    elif message_type == "leave group":
        send_data_bytes, hash_int = build_leave_message(device, message_type)
    else:
        return

    choose_addresses_length = len(choose_chain_addresses)
    require_num = int((choose_addresses_length - 1) / 3 + 1)

    start_index = hash_int % choose_addresses_length

    choose_addresses = []
    for i in range(require_num):
        choose_addresses.append(
            choose_chain_addresses[(start_index + i) % choose_addresses_length]
        )

    random.shuffle(choose_addresses)
    thread_list = []
    for choose_address in choose_addresses:
        choose_address_ip = get_ip_by_address(choose_address, choose_chain_id)
        send_thread = threading.Thread(
            target=just_send_data,
            args=(choose_address_ip, send_data_bytes),
        )
        thread_list.append(send_thread)

    for send_thread in thread_list:
        send_thread.start()

    for send_thread in thread_list:
        send_thread.join()


def build_join_message(device, message_type):
    timestamp = int(datetime.datetime.today().timestamp())

    format_cert_sign = (
        web3.to_hex(device[1][8].messageHash),
        to_32byte_hex(device[1][8].r),
        to_32byte_hex(device[1][8].s),
        device[1][8].v,
    )
    cert_sign_hash = web3.solidity_keccak(
        ["bytes32", "bytes32", "bytes32", "uint8", "bytes"],
        [
            format_cert_sign[0],
            format_cert_sign[1],
            format_cert_sign[2],
            format_cert_sign[3],
            device[1][8][4],
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
            device[1][0],
            device[1][1],
            device[1][2],
            device[1][3],
            device[1][4],
            device[1][5],
            device[1][6],
            device[1][7],
            cert_sign_hash,
        ],
    )

    send_message_hash = web3.solidity_keccak(
        ["uint256", "bytes32"], [timestamp, cert_message_hash]
    )
    request_message_type = encode_defunct(send_message_hash)
    send_message_sign = web3.eth.account.sign_message(
        request_message_type, private_key=device[0]
    )
    send_data = [
        message_type,
        timestamp,
        device[1],
        send_message_sign,
    ]

    send_data_bytes = pickle.dumps(send_data)

    hash_int = int.from_bytes(send_message_hash, byteorder="big")

    return send_data_bytes, hash_int


def to_32byte_hex(val):
    return web3.to_hex(web3.to_bytes(val).rjust(32, b"\0"))


def build_leave_message(device, message_type):
    timestamp = int(datetime.datetime.today().timestamp())

    send_message_hash = web3.solidity_keccak(["uint256"], [timestamp])
    request_message_type = encode_defunct(send_message_hash)
    send_message_sign = web3.eth.account.sign_message(
        request_message_type, private_key=device[0]
    )
    send_data = [
        message_type,
        timestamp,
        send_message_sign,
    ]

    send_data_bytes = pickle.dumps(send_data)

    hash_int = int.from_bytes(send_message_hash, byteorder="big")

    return send_data_bytes, hash_int

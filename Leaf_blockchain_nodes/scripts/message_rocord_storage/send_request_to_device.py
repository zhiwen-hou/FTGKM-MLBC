# Send a message log request to the device

from brownie import web3, MessageRecordStorage, GroupKeyManagement, GroupMessageStorage
import datetime
import pickle
import random
import threading
import socket
from scripts.configure_basic_parameters.adjacent_chains import SELF_CHAIN_ID
from eth_account.messages import encode_defunct


def send_request_to_device(
    trigger_hash,
    block_timestamp,
    trigger_num,
    require_num,
    account,
    account_num,
    lock,
):
    message_record_storage = MessageRecordStorage[-1]
    group_key_management = GroupKeyManagement[-1]

    send_message_hash = web3.solidity_keccak(
        ["uint256", "bytes32"], [block_timestamp, trigger_hash]
    )
    request_message_type = encode_defunct(send_message_hash)
    send_message_sign = web3.eth.account.sign_message(
        request_message_type, private_key=account.private_key
    )
    send_message_hash_sign_hash = web3.solidity_keccak(
        ["bytes"], [send_message_sign.signature]
    )
    request_message_type = encode_defunct(trigger_hash)

    send_data = [
        "request record",
        SELF_CHAIN_ID,
        block_timestamp,
        trigger_hash,
        send_message_sign,
    ]
    send_data_bytes = pickle.dumps(send_data)

    device_addresses_tuple = group_key_management.getDeviceAddresses(
        {"from": account, "required_confs": 0}
    )
    device_addresses_list = list(device_addresses_tuple)

    device_addresses_length = len(device_addresses_list)
    require_num = require_num * 2
    start_index = trigger_num % device_addresses_length
    choose_addresses = []
    for i in range(require_num):
        choose_addresses.append(
            device_addresses_list[(start_index + i) % device_addresses_length]
        )

    random.shuffle(choose_addresses)

    for device_address in choose_addresses:
        send_thread = threading.Thread(
            target=send_data_to_device,
            args=(
                trigger_hash,
                block_timestamp,
                message_record_storage,
                group_key_management,
                send_message_sign,
                send_message_hash_sign_hash,
                device_address,
                account,
                account_num,
                send_data_bytes,
                request_message_type,
                lock,
            ),
        )
        send_thread.start()


def send_data_to_device(
    trigger_hash,
    block_timestamp,
    message_record_storage,
    group_key_management,
    send_message_sign,
    send_message_hash_sign_hash,
    device_address,
    account,
    account_num,
    send_data_bytes,
    request_message_type,
    lock,
):
    device_ip = group_key_management.getDeviceIp(
        device_address, {"from": account, "required_confs": 0}
    )
    try:
        socket_client = socket.socket()
        socket_client.connect(("", int(device_ip)))
        socket_client.sendall(send_data_bytes)

        socket_client.settimeout(30)

        loop_data = b""
        while True:
            loop_part = socket_client.recv(2048)
            loop_data += loop_part
            if len(loop_part) < 2048:
                break
        received_data_bytes = loop_data
        socket_client.close()
    except Exception as e:
        received_data_bytes = b""
        handle_result = False
        result_content = f"An error occurred connecting to choose_address: {e}".encode()
    else:
        received_data = pickle.loads(received_data_bytes)
        received_handle_result = received_data[0]
        received_result_content = received_data[1]
        received_record_hash_list = received_data[2]
        received_signer_list = received_data[3]

        if received_handle_result.decode() == "failure":
            handle_result = False
            result_content = f"listening_sign_completed received failure result: {received_result_content.decode()}".encode()
        else:
            bytes32_type_list = ["bytes32"] * len(received_record_hash_list)
            received_record_hash_list_hash = web3.solidity_keccak(
                bytes32_type_list, received_record_hash_list
            )
            address_type_list = ["address"] * len(received_signer_list)
            received_signer_list_hash = web3.solidity_keccak(
                address_type_list, received_signer_list
            )
            received_message_hash = web3.solidity_keccak(
                ["bytes32", "bytes32", "bytes32"],
                [
                    send_message_hash_sign_hash,
                    received_record_hash_list_hash,
                    received_signer_list_hash,
                ],
            )
            request_message_type = encode_defunct(received_message_hash)
            signer = web3.eth.account.recover_message(
                request_message_type, signature=received_result_content.signature
            )
            if signer != device_address:
                handle_result = False
                result_content = (
                    "listening_sign_completed received wrong contersign".encode()
                )
            else:
                handle_result = True
                result_content = received_result_content

    if handle_result is not True:
        if result_content.decode().find("The message has been processed") == -1:
            log_datetime = datetime.datetime.today().strftime("%Y%m%d")
            file_name = f"./runtimedata/exceptions/account{str(account_num).zfill(2)}/{log_datetime}_send_request_to_device.txt"
            with open(file_name, "a") as f:
                time_now = int(datetime.datetime.today().timestamp())
                f.write(str(time_now))
                f.write("\n")
                f.write(send_data_bytes.hex())
                f.write("\n")
                f.write(device_ip)
                f.write("\n")
                f.write(received_data_bytes.hex())
                f.write("\n")
                f.write(result_content.decode())
                f.write("\n")
                f.flush()
    else:
        try:
            with lock:
                message_record_storage.storeDeviceRecord(
                    trigger_hash,
                    block_timestamp,
                    send_message_sign,
                    result_content,
                    received_record_hash_list,
                    received_signer_list,
                    {"from": account, "required_confs": 0},
                )
        except Exception as e:
            if (
                str(e).find("Countersign already exists") == -1
                and str(e).find("There are incorrect deviceCounertsign") == -1
            ):
                print(
                    f"{int(datetime.datetime.today().timestamp())} MessageRecordStorage's error: {e}"
                )

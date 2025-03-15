from brownie import web3, config
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from collections import deque
import threading
import multiprocessing
import random
import time
import socket
import pickle
import datetime
import base64
from scripts.leaf_blockchain import (
    LEAF_CHAIN_IDS,
    LEAF_CHAIN_LEVEL,
    get_addresses,
    get_public_key_by_address,
)
from scripts.send_data_to_chain import send_group_message, send_request_message
from eth_account.messages import encode_defunct


class MessageBuffer:
    def __init__(self, capacity):
        self.capacity = capacity
        self.buffer = deque(maxlen=capacity)
        self.message_set = set()
        self.lock = threading.Lock()

    def add_message(self, record_hash, signer):
        with self.lock:
            if record_hash in self.message_set:
                return False

            if len(self.buffer) >= self.capacity:
                oldest_message = self.buffer.popleft()
                self.message_set.remove(oldest_message[0])

            self.buffer.append((record_hash, signer))
            self.message_set.add(record_hash)
            return True

    def clear(self):
        with self.lock:
            self.buffer.clear()
            self.message_set.clear()

    def get_record(self):
        with self.lock:
            return [record_hash for record_hash, _ in self.buffer], [
                signer for _, signer in self.buffer
            ]


# Defining device classes
class DeviceOperation:
    # Pass in device information and initialize device parameters
    def __init__(self, device) -> None:
        self.device = device
        self.group_key = None
        # Used to store the status of the device, i.e. whether it is in the group or not
        self.status = 0
        self.message_buffer = MessageBuffer(50)
        # Used to store the chain ID of the leaf blockchain
        self.choose_chain_id = 0
        self.choose_chain_addresses = []
        # Used to store request messages to avoid processing duplicate requests
        self.request_list = []
        self.device_info_lock = threading.Lock()
        self.group_ips = []

    def start_the_decice(self):
        thread_run = threading.Thread(target=self.run_the_device)
        thread_listener = threading.Thread(target=self.message_listener)
        thread_run.start()
        thread_listener.start()

    # Start device class
    def run_the_device(self):
        while True:
            time.sleep(random.randint(10, 30))
            new_status = random.random()
            if self.status < 0.3 and new_status < 0.3:
                time.sleep(random.randint(60, 300))
            elif self.status < 0.3 and new_status >= 0.3:
                self.choose_chain_id = random.choice(LEAF_CHAIN_IDS)
                self.choose_chain_addresses = get_addresses(self.choose_chain_id)

                # Send a request to join
                message_type = "join group"
                send_request_message(
                    self.device,
                    self.choose_chain_id,
                    message_type,
                    self.choose_chain_addresses,
                )

                time.sleep(10)

                # Send a group message
                time_in_group = 0
                time_in_group_count = random.randint(60, 300)
                while time_in_group < time_in_group_count:
                    if self.group_key != None:
                        message_type = "group message"
                        send_group_message(
                            self.device,
                            self.choose_chain_id,
                            message_type,
                            self.group_key,
                            self.choose_chain_addresses,
                            self.group_ips,
                        )

                    interval_time = random.randint(30, 60)
                    time.sleep(interval_time)
                    time_in_group += interval_time
            elif self.status >= 0.3 and new_status < 0.3:
                # Send a leave request
                message_type = "leave group"
                send_request_message(
                    self.device,
                    self.choose_chain_id,
                    message_type,
                    self.choose_chain_addresses,
                )

                # Clear the group key and message cache
                with self.device_info_lock:
                    self.group_key = None
                    self.group_ips.clear()
                self.message_buffer.clear()

                time.sleep(random.randint(60, 300))
            else:
                # Send a group message
                time_in_group = 0
                time_in_group_count = random.randint(60, 300)
                while time_in_group < time_in_group_count:
                    if self.group_key != None:
                        message_type = "group message"
                        send_group_message(
                            self.device,
                            self.choose_chain_id,
                            message_type,
                            self.group_key,
                            self.choose_chain_addresses,
                            self.group_ips,
                        )

                    interval_time = random.randint(30, 60)
                    time.sleep(interval_time)
                    time_in_group += interval_time

            self.status = new_status

    # Handling group key messages
    def handle_group_key_message(self, received_data):
        received_message_type = received_data[0]
        sender_chain_id = received_data[1]
        received_timestamp = received_data[2]
        received_hash = received_data[3]
        received_message = received_data[4]
        received_message_sign = received_data[5]

        # When you just join a group and have not received the group key, do not receive group messages
        if received_message_type != "group key" and self.group_key == None:
            return

        # Check if the chain ID is correct
        if sender_chain_id != self.choose_chain_id:
            return

        now_timestamp = int(datetime.datetime.today().timestamp())
        if now_timestamp - received_timestamp > config["default_timeout"]:
            return

        received_message_hash = web3.solidity_keccak(
            ["uint256", "bytes32"], [received_timestamp, received_hash]
        )

        request_message_type = encode_defunct(received_message_hash)
        signer = web3.eth.account.recover_message(
            request_message_type, signature=received_message_sign.signature
        )
        hash_int = int.from_bytes(received_message_hash, byteorder="big")
        leaf_chain_addresses = self.choose_chain_addresses
        leaf_chain_addresses_length = len(leaf_chain_addresses)
        require_num = int((leaf_chain_addresses_length - 1) / 3 + 1)
        start_index = hash_int % leaf_chain_addresses_length
        choose_addresses = []
        for i in range(require_num):
            choose_addresses.append(
                leaf_chain_addresses[(start_index + i) % leaf_chain_addresses_length]
            )
        if signer not in choose_addresses:
            return

        # Check if the message has been received
        if self.message_buffer.add_message(received_message_hash, signer) is not True:
            return

        self_private_key = ec.derive_private_key(
            int.from_bytes(self.device[0], byteorder="big"), ec.SECP256K1()
        )
        leaf_public_key_nytes = get_public_key_by_address(signer, self.choose_chain_id)
        leaf_public_key = serialization.load_pem_public_key(leaf_public_key_nytes)
        shared_key = self_private_key.exchange(ec.ECDH(), leaf_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=received_hash,
        ).derive(shared_key)
        derived_key_base64 = base64.urlsafe_b64encode(derived_key)
        derived_key_fernet = Fernet(derived_key_base64)

        # Decrypting group key
        try:
            new_group_key = derived_key_fernet.decrypt(received_message)
        except Exception as e:
            print(
                f"{datetime.datetime.now()}: Device{str(self.device[1][0]).zfill(3)} had an error decrypting the group key-{self.group_key}"
            )
        else:
            # Verify that the decrypted group key is correct
            new_group_key_hash = web3.solidity_keccak(["bytes"], [new_group_key])
            if new_group_key_hash != received_hash:
                return

            try:
                new_group_key_frenet = Fernet(new_group_key)
                # Update group key and group key hash
                with self.device_info_lock:
                    self.group_key = new_group_key_frenet
                    self.group_ips = received_data[6]
            except:
                print(
                    f"{datetime.datetime.now()}: the group key-{new_group_key} for Device{str(self.device[1][0]).zfill(3)} is wrong"
                )

    # Handling group messages
    def handle_group_messsage_message(self, received_data):
        received_message_type = received_data[0]
        sender_chain_id = received_data[1]
        received_timestamp = received_data[2]
        received_hash = received_data[3]
        received_message = received_data[4]
        received_message_sign = received_data[5]
        received_message_level = received_data[6]

        if received_message_type != "group key" and self.group_key == None:
            return

        if received_message_level == LEAF_CHAIN_LEVEL:
            now_timestamp = int(datetime.datetime.today().timestamp())
            if now_timestamp - received_timestamp > config["default_timeout"]:
                return

            try:
                group_message = self.group_key.decrypt(received_message)
            except:
                return
            else:
                # Verify that the decrypted group message is correct
                group_message_hash = web3.solidity_keccak(["bytes"], [group_message])
                if group_message_hash != received_hash:
                    return
        else:
            if sender_chain_id != self.choose_chain_id:
                return

            now_timestamp = int(datetime.datetime.today().timestamp())
            if now_timestamp - received_timestamp > config["default_timeout"]:
                return

            received_message_hash = web3.solidity_keccak(
                ["uint256", "uint256", "bytes32"],
                [received_message_level, received_timestamp, received_hash],
            )

            request_message_type = encode_defunct(received_message_hash)
            signer = web3.eth.account.recover_message(
                request_message_type, signature=received_message_sign.signature
            )
            hash_int = int.from_bytes(received_message_hash, byteorder="big")
            leaf_chain_addresses = self.choose_chain_addresses
            leaf_chain_addresses_length = len(leaf_chain_addresses)
            require_num = int((leaf_chain_addresses_length - 1) / 3 + 1)
            start_index = hash_int % leaf_chain_addresses_length
            choose_addresses = []
            for i in range(require_num):
                choose_addresses.append(
                    leaf_chain_addresses[
                        (start_index + i) % leaf_chain_addresses_length
                    ]
                )
            if signer not in choose_addresses:
                return

            if (
                self.message_buffer.add_message(received_message_hash, signer)
                is not True
            ):
                return

            try:
                group_message = self.group_key.decrypt(received_message)
            except:
                return
            else:
                group_message_hash = web3.solidity_keccak(["bytes"], [group_message])
                if group_message_hash != received_hash:
                    return

                print(
                    f"{datetime.datetime.now().timestamp()}：{str(self.device[1][0]).zfill(3)}接收到了{self.choose_chain_id}的{received_message_level}层级的群组消息: {group_message}"
                )

    # Process blockchain node change messages
    def handle_new_address_message(self, received_data):
        received_message_type = received_data[0]
        sender_chain_id = received_data[1]
        received_timestamp = received_data[2]
        received_hash = received_data[3]
        received_message = received_data[4]
        received_message_sign = received_data[5]

        if received_message_type != "group key" and self.group_key == None:
            return

        if sender_chain_id != self.choose_chain_id:
            return

        now_timestamp = int(datetime.datetime.today().timestamp())
        if now_timestamp - received_timestamp > config["default_timeout"]:
            return

        received_message_hash = web3.solidity_keccak(
            ["uint256", "bytes32"], [received_timestamp, received_hash]
        )

        request_message_type = encode_defunct(received_message_hash)
        signer = web3.eth.account.recover_message(
            request_message_type, signature=received_message_sign.signature
        )
        hash_int = int.from_bytes(received_message_hash, byteorder="big")
        leaf_chain_addresses = self.choose_chain_addresses
        leaf_chain_addresses_length = len(leaf_chain_addresses)
        require_num = int((leaf_chain_addresses_length - 1) / 3 + 1)
        start_index = hash_int % leaf_chain_addresses_length
        choose_addresses = []
        for i in range(require_num):
            choose_addresses.append(
                leaf_chain_addresses[(start_index + i) % leaf_chain_addresses_length]
            )
        if signer not in choose_addresses:
            return

        if self.message_buffer.add_message(received_message_hash, signer) is not True:
            return

        changed_address_hash = web3.solidity_keccak(["address"], [received_message])

        # Verify that the hash of the change address is correct
        if changed_address_hash != received_hash:
            return

        # Changing the Address List
        if received_message in self.choose_chain_addresses:
            self.choose_chain_addresses.remove(received_message)
        else:
            self.choose_chain_addresses.append(received_message)

    # Processing message record request
    def handle_request_record_message(self, received_data, sender_socket):
        handle_result, result_content, record_hash_list, signer_list = (
            self.verify_request_record_message(received_data)
        )

        send_data = [handle_result, result_content, record_hash_list, signer_list]
        send_data_bytes = pickle.dumps(send_data)

        try:
            sender_socket.sendall(send_data_bytes)
            sender_socket.close()
        except Exception as e:
            print(
                f"{datetime.datetime.now()}: Device{str(self.device[1][0]).zfill(3)} had an error handling the request record-{received_data[2]}"
            )

    # Verify message record request
    def verify_request_record_message(self, received_data):
        sender_chain_id = received_data[1]
        received_block_timestamp = received_data[2]
        received_trigger_hash = received_data[3]
        received_message_sign = received_data[4]

        record_hash_list = []
        signer_list = []

        now_timestamp = int(datetime.datetime.today().timestamp())
        if now_timestamp - received_block_timestamp > config["default_timeout"]:
            return

        if sender_chain_id != self.choose_chain_id:
            handle_result = "failure".encode()
            result_content = "There is incorrect chain_id".encode()
            return handle_result, result_content, record_hash_list, signer_list

        received_message_hash = web3.solidity_keccak(
            ["uint256", "bytes32"], [received_block_timestamp, received_trigger_hash]
        )

        request_message_type = encode_defunct(received_message_hash)
        signer = web3.eth.account.recover_message(
            request_message_type, signature=received_message_sign.signature
        )
        leaf_chain_addresses = self.choose_chain_addresses
        leaf_chain_addresses_length = len(leaf_chain_addresses)
        require_num = int((leaf_chain_addresses_length - 1) / 3 + 1)
        received_trigger_num = int.from_bytes(received_trigger_hash, byteorder="big")
        start_index = received_trigger_num % leaf_chain_addresses_length
        choose_addresses = []
        for i in range(require_num):
            choose_addresses.append(
                leaf_chain_addresses[(start_index + i) % leaf_chain_addresses_length]
            )
        if signer not in choose_addresses:
            handle_result = "failure".encode()
            result_content = "Sender's signature is incorrect".encode()
            return handle_result, result_content, record_hash_list, signer_list

        if self.message_buffer.add_message(received_message_hash, signer) is not True:
            handle_result = "failure".encode()
            result_content = "The message has been processed".encode()
            # print("The message has been processed")
            return handle_result, result_content, record_hash_list, signer_list

        print(
            f"{datetime.datetime.now().timestamp()}：{str(self.device[1][0]).zfill(3)}接收到了{self.choose_chain_id}的请求消息记录消息: {received_trigger_num}"
        )

        # Constructs a message and returns it
        handle_result = "success".encode()
        record_hash_list, signer_list = self.message_buffer.get_record()
        bytes32_type_list = ["bytes32"] * len(record_hash_list)
        record_hash_list_hash = web3.solidity_keccak(
            bytes32_type_list, record_hash_list
        )
        address_type_list = ["address"] * len(signer_list)
        signer_list_hash = web3.solidity_keccak(address_type_list, signer_list)
        received_message_sign_hash = web3.solidity_keccak(
            ["bytes"], [received_message_sign.signature]
        )
        send_message_hash = web3.solidity_keccak(
            ["bytes32", "bytes32", "bytes32"],
            [received_message_sign_hash, record_hash_list_hash, signer_list_hash],
        )
        request_message_type = encode_defunct(send_message_hash)
        send_message_sign = web3.eth.account.sign_message(
            request_message_type, private_key=self.device[0]
        )
        result_content = send_message_sign
        return handle_result, result_content, record_hash_list, signer_list

    # Process received messages according to their type
    def handle_received_data(self, sender_socket):
        try:
            loop_data = b""
            while True:
                loop_part = sender_socket.recv(2048)
                loop_data += loop_part
                if len(loop_part) < 2048:
                    break
            received_data_bytes = loop_data
            received_data = pickle.loads(received_data_bytes)
        except Exception as e:
            pass
        else:
            received_message_type = received_data[0]
            if received_message_type == "request record":
                self.handle_request_record_message(received_data, sender_socket)
            elif received_message_type == "group key":
                self.handle_group_key_message(received_data)
            elif received_message_type == "group message":
                self.handle_group_messsage_message(received_data)
            elif received_message_type == "new address":
                self.handle_new_address_message(received_data)

    def message_listener(self):
        receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        receiver_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        receiver_socket.bind(("", int(self.device[1][1])))
        receiver_socket.listen(128)

        while True:
            sender_socket, sender_address = receiver_socket.accept()
            sub_thread = threading.Thread(
                target=self.handle_received_data,
                args=(sender_socket,),
            )
            sub_thread.start()


# Read device information
def load_device(str_num="000"):
    with open(f"./configdata/device_info/device{str_num}.bin", "rb") as f:
        device = pickle.load(f)
    return device


# Start the device
def start_the_device():
    device = load_device(str(0).zfill(3))
    device_operation = DeviceOperation(device)
    device_process = multiprocessing.Process(target=device_operation.start_the_decice)
    device_process.start()


def main():
    start_the_device()


if __name__ == "__main__":
    main()

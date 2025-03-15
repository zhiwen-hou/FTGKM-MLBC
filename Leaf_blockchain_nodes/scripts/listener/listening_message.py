# Receive group messages

from brownie import accounts
import socket
import threading
import pickle
import datetime
from collections import deque
from scripts.listener.handle_received_message import (
    handle_join_group_message,
    handle_leave_group_message,
    handle_parent_group_message,
    handle_devices_group_message,
)
from scripts.configure_basic_parameters.addresses_and_ips import get_ip_by_address


# Define the message buffer queue
class MessageBuffer:
    def __init__(self, capacity):
        self.capacity = capacity
        self.buffer_set = set()
        self.buffer_queue = deque()
        self.lock = threading.Lock()

    def add_message(self, message_info):
        # Ensure that operations on the buffer are thread-safe
        with self.lock:
            if message_info in self.buffer_set:
                return False
            else:
                if len(self.buffer_set) >= self.capacity:
                    oldest_message_info = self.buffer_queue.popleft()
                    self.buffer_set.remove(oldest_message_info)

                # Add new message information
                self.buffer_set.add(message_info)
                self.buffer_queue.append(message_info)
                return True


class ServerMessageListener:
    def __init__(self, account_num) -> None:
        self.message_buffer = MessageBuffer(50)
        self.account_num = account_num

    # Listen for messages sent by devices or other servers
    def listening_message(self, lock):
        account = accounts[self.account_num]
        receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        receiver_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        receiver_socket.bind(("", int(get_ip_by_address(account.address))))
        receiver_socket.listen(128)

        # print(f"Listening for network message...")

        while True:
            sender_socket, sender_address = receiver_socket.accept()
            sub_thread = threading.Thread(
                target=handle_received_data,
                args=(
                    sender_socket,
                    sender_address,
                    account,
                    self.account_num,
                    self.message_buffer,
                    lock,
                ),
            )
            sub_thread.start()


# Processing received data
def handle_received_data(
    sender_socket, sender_address, account, account_num, message_buffer, lock
):
    try:
        loop_data = b""
        while True:
            loop_part = sender_socket.recv(2048)
            loop_data += loop_part
            if len(loop_part) < 2048:
                break
        received_data_bytes = loop_data
    except Exception as e:
        error_info = f"An error occurred connecting to sender: {e}".encode()
        log_datetime = datetime.datetime.today().strftime("%Y%m%d")
        file_name = f"./runtimedata/exceptions/account{str(account_num).zfill(2)}/{log_datetime}_listening_message.txt"
        with open(file_name, "a") as f:
            time_now = int(datetime.datetime.today().timestamp())
            f.write(str(time_now))
            f.write("\n")
            f.write(b"".hex())
            f.write("\n")
            f.write(error_info.hex())
            f.write("\n")
            f.flush()
    else:
        # Process the received data according to the message type
        received_data = pickle.loads(received_data_bytes)
        received_message_type = received_data[0]

        if received_message_type == "join group":
            handle_join_group_message(received_data, account, account_num, lock)
        if received_message_type == "leave group":
            handle_leave_group_message(received_data, account, account_num, lock)
        if received_message_type == "group message":
            sender_chain_id = received_data[1]
            if sender_chain_id <= 1000:
                handle_devices_group_message(
                    sender_socket, received_data, account, account_num, lock
                )
            else:
                handle_parent_group_message(
                    sender_socket,
                    sender_address,
                    received_data,
                    account,
                    account_num,
                    message_buffer,
                    lock,
                )


def message_listener(account_num, lock):
    server_message_listener = ServerMessageListener(account_num)
    server_message_listener.listening_message(lock)


def main():
    message_listener()


if __name__ == "__main__":
    main()

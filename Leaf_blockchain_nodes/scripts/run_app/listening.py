import multiprocessing
from scripts.group_key_management.init import init_device_addresses
from scripts.contribution_storage.calculate_contribution_ratio import (
    init_reputation,
)
from scripts.group_key_management.listening_group_key_updated import (
    group_key_updated_listener,
)
from scripts.contribution_storage.listening_request_record import (
    request_record_listener,
)
from scripts.contribution_storage.listening_malicious_nodes_found import (
    malicious_nodes_found_listener,
)
from scripts.listener.listening_message import message_listener
from web3.middleware import geth_poa_middleware
from brownie import network, accounts, config
import time


# Start the node
def start_server_method():
    lock = multiprocessing.Lock()

    process_list = []
    account_num = 0

    # Listen for group key update completion events
    group_key_updated_listener_process = multiprocessing.Process(
        target=group_key_updated_listener, args=(account_num,)
    )

    # Monitor device message logging request events
    request_record_listener_precess = multiprocessing.Process(
        target=request_record_listener, args=(account_num, lock)
    )

    # Monitor malicious node discovery events
    malicious_nodes_found_listener_process = multiprocessing.Process(
        target=malicious_nodes_found_listener,
        args=(account_num,),
    )

    # Listening for network messages
    message_listener_process = multiprocessing.Process(
        target=message_listener, args=(account_num, lock)
    )

    group_key_updated_listener_process.name = (
        f"group_key_updated_listener_{account_num}"
    )
    request_record_listener_precess.name = f"request_record_listener_{account_num}"
    malicious_nodes_found_listener_process.name = (
        f"malicious_nodes_found_listener_process{account_num}"
    )
    message_listener_process.name = f"message_listener_{account_num}"

    process_list.append(group_key_updated_listener_process)
    process_list.append(request_record_listener_precess)
    process_list.append(malicious_nodes_found_listener_process)
    process_list.append(message_listener_process)

    for server_process in process_list:
        server_process.start()

    for server_process in process_list:
        server_process.join()


def main():
    network.web3.middleware_onion.inject(geth_poa_middleware, layer=0)

    accounts.add(config["keys"]["private_key"])

    # init_device_addresses()

    # init_reputation()

    start_server_method()

    pass


if __name__ == "__main__":
    main()

import multiprocessing
import time
from scripts.contribution_storage.calculate_contribution_ratio import (
    init_reputation,
)
from scripts.contribution_storage.listening_malicious_nodes_found import (
    malicious_nodes_found_listener,
)
from scripts.listener.listening_message import message_listener
from scripts.configure_basic_parameters.addresses_and_ips import get_addresses_length
from web3.middleware import geth_poa_middleware
from brownie import network, accounts, config


def start_server():
    lock = multiprocessing.Lock()

    process_list = []
    account_num = 0

    malicious_nodes_found_listener_process = multiprocessing.Process(
        target=malicious_nodes_found_listener, args=(account_num,)
    )

    message_listener_process = multiprocessing.Process(
        target=message_listener, args=(account_num, lock)
    )

    process_list.append(malicious_nodes_found_listener_process)
    process_list.append(message_listener_process)

    for server_process in process_list:
        server_process.start()

    for server_process in process_list:
        server_process.join()


def main():
    network.web3.middleware_onion.inject(geth_poa_middleware, layer=0)

    accounts.add(config["keys"]["private_key"])

    init_reputation()

    start_server()


if __name__ == "__main__":
    main()

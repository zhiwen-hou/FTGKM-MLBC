# Listen for message logging request events

from brownie import ContributionStorage, accounts
import threading
from scripts.configure_basic_parameters.addresses_and_ips import get_addresses
from scripts.message_rocord_storage.send_request_to_device import send_request_to_device


def request_record_listener(account_num, lock):

    account = accounts[account_num]
    contribution_storage = ContributionStorage[-1]
    event_name = "RequestRecord"
    event_filter = contribution_storage.events[event_name].create_filter(
        fromBlock="latest"
    )
    print(f"Listening for '{event_name}' events...")
    while True:
        for event in event_filter.get_new_entries():
            # Extract the group key hash from the event
            trigger_hash = event.args.triggerHash
            block_timestamp = event.args.blockTimestamp

            # Calculating hash tables
            trigger_num = int.from_bytes(trigger_hash, byteorder="big")
            self_addresses = get_addresses()
            self_addresses_length = len(self_addresses)
            require_num = int((self_addresses_length - 1) / 3 + 1)
            start_index = trigger_num % self_addresses_length
            choose_addresses = []
            for i in range(require_num):
                choose_addresses.append(
                    self_addresses[(start_index + i) % self_addresses_length]
                )

            # If it is in the selected address, forward it
            if account.address in choose_addresses:
                # Send message record request
                thread_send_merge_hash_to_parent = threading.Thread(
                    target=send_request_to_device,
                    args=(
                        trigger_hash,
                        block_timestamp,
                        trigger_num,
                        require_num,
                        account,
                        account_num,
                        lock,
                    ),
                )
                thread_send_merge_hash_to_parent.start()


def main():
    request_record_listener()


if __name__ == "__main__":
    main()

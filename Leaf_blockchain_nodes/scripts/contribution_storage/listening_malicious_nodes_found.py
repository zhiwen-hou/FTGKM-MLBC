# Monitor different malicious nodes to discover events

from brownie import ContributionStorage


def malicious_nodes_found_listener(account_num):

    # Creating an event listener
    contribution_storage = ContributionStorage[-1]
    event_name = "MaliciousNodesFound"
    event_filter = contribution_storage.events[event_name].create_filter(
        fromBlock="latest"
    )
    print(f"Listening for '{event_name}' events...")
    while True:
        for event in event_filter.get_new_entries():
            # Extract malicious node addresses and their reputation values ​​from events
            malicious_node_address = event.args.malicious
            malicious_node_reputation = event.args.reputation

            # Currently, only malicious nodes are detected.
            # Specific processing operations can be added here as required.
            print(
                f"{account_num}-Malicious node detected: {malicious_node_address}-{malicious_node_reputation}"
            )


def fake_message_malicious_nodes_found_listener(account_num):

    contribution_storage = ContributionStorage[-1]
    event_name = "FakeMessageMaliciousNodesFound"
    event_filter = contribution_storage.events[event_name].create_filter(
        fromBlock="latest"
    )
    print(f"Listening for '{event_name}' events...")
    while True:
        for event in event_filter.get_new_entries():
            malicious_node_address = event.args.malicious
            malicious_node_reputation = event.args.reputation

            print(
                f"{account_num}-Malicious node detected: {malicious_node_address}-{malicious_node_reputation}"
            )


def group_key_malicious_nodes_found_listener(account_num):

    contribution_storage = ContributionStorage[-1]
    event_name = "GroupKeyMaliciousNodesFound"
    event_filter = contribution_storage.events[event_name].create_filter(
        fromBlock="latest"
    )
    print(f"Listening for '{event_name}' events...")
    while True:
        for event in event_filter.get_new_entries():
            malicious_node_address = event.args.malicious
            malicious_node_reputation = event.args.reputation

            print(
                f"{account_num}-Group key malicious node detected: {malicious_node_address}-{malicious_node_reputation}"
            )


def group_message_malicious_nodes_found_listener(account_num):

    contribution_storage = ContributionStorage[-1]
    event_name = "GroupMessageMaliciousNodesFound"
    event_filter = contribution_storage.events[event_name].create_filter(
        fromBlock="latest"
    )
    print(f"Listening for '{event_name}' events...")
    while True:
        for event in event_filter.get_new_entries():
            malicious_node_address = event.args.malicious
            malicious_node_reputation = event.args.reputation

            print(
                f"{account_num}-Group message malicious node detected: {malicious_node_address}-{malicious_node_reputation}"
            )


def main():
    malicious_nodes_found_listener()
    fake_message_malicious_nodes_found_listener()
    group_key_malicious_nodes_found_listener()
    group_message_malicious_nodes_found_listener()


if __name__ == "__main__":
    main()

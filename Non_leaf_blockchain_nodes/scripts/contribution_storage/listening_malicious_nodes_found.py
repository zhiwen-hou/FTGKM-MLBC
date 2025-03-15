from brownie import ContributionStorage


def malicious_nodes_found_listener(account_num):
    contribution_storage = ContributionStorage[-1]
    event_name = "MaliciousNodesFound"
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


def main():
    malicious_nodes_found_listener()


if __name__ == "__main__":
    main()

from brownie import (
    PublicKeyStorage,
    GroupKeyManagement,
    GroupMessageStorage,
    ContributionStorage,
    accounts,
    config,
)


def deploy_group_message_storage():
    account = accounts.add(config["keys"]["admin_private_key"])
    group_message_storage = GroupMessageStorage.deploy(
        PublicKeyStorage[-1],
        GroupKeyManagement[-1],
        ContributionStorage[-1],
        config["default_timeout"],
        config["trigger_threshold"],
        config["triggering_conditions"],
        {"from": account},
    )
    print("Group message storage contract has been deployed")
    return group_message_storage


def main():
    deploy_group_message_storage()


if __name__ == "__main__":
    main()

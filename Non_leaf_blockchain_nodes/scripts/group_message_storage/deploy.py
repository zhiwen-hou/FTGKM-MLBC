from brownie import (
    PublicKeyStorage,
    GroupMessageStorage,
    ContributionStorage,
    accounts,
    config,
)


def deploy_group_message_storage():
    account = accounts.add(config["keys"]["admin_private_key"])
    group_message_storage = GroupMessageStorage.deploy(
        PublicKeyStorage[-1],
        ContributionStorage[-1],
        config["default_timeout"],
        config["trigger_threshold"],
        config["triggering_conditions"],
        {"from": account},
    )
    return group_message_storage


def main():
    deploy_group_message_storage()


if __name__ == "__main__":
    main()

from brownie import (
    PublicKeyStorage,
    GroupKeyManagement,
    accounts,
    config,
    ContributionStorage,
)


def deploy_group_key_management():
    account = accounts.add(config["keys"]["admin_private_key"])
    group_key_management = GroupKeyManagement.deploy(
        PublicKeyStorage[-1],
        ContributionStorage[-1],
        config["default_timeout"],
        config["trigger_threshold"],
        config["triggering_conditions"],
        {"from": account},
    )
    print("Group key management contract deployed")
    return group_key_management


def main():
    deploy_group_key_management()


if __name__ == "__main__":
    main()

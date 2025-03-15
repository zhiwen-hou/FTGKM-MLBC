from brownie import (
    PublicKeyStorage,
    GroupKeyManagement,
    GroupMessageStorage,
    MessageRecordStorage,
    ContributionStorage,
    accounts,
    config,
)


def deploy_message_record_storage():
    account = accounts.add(config["keys"]["admin_private_key"])
    message_record_storage = MessageRecordStorage.deploy(
        PublicKeyStorage[-1],
        GroupKeyManagement[-1],
        GroupMessageStorage[-1],
        ContributionStorage[-1],
        {"from": account},
    )
    print("The message record storage contract has been deployed")
    return message_record_storage


def main():
    deploy_message_record_storage()


if __name__ == "__main__":
    main()

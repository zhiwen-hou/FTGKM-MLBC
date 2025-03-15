from brownie import accounts, GroupMessageStorage, config


def get_countersigns():
    account = accounts.add(config["keys"]["admin_private_key"])
    group_message_storage = GroupMessageStorage[-1]

    pass


def main():
    get_countersigns()


if __name__ == "__main__":
    main()

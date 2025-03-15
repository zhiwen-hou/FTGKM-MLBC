from brownie import accounts, GroupKeyManagement, config


def init_device_addresses():
    account = accounts.add(config["keys"]["admin_private_key"])
    group_key_management = GroupKeyManagement[-1]

    group_key_management.initDeviceAndGroupKey({"from": account})

    print("The device list has been cleared")


def main():
    init_device_addresses()

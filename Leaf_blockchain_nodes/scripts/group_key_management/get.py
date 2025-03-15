from brownie import accounts, GroupKeyManagement, config


def get_device_addresses():
    account = accounts.add(config["keys"]["admin_private_key"])
    group_key_management = GroupKeyManagement[-1]

    device_addresses = group_key_management.getDeviceAddresses(
        {"from": account, "required_confs": 0}
    )
    print(f"device_addresses={device_addresses}")


def main():
    get_device_addresses()

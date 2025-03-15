from brownie import accounts, GroupKeyManagement, config, network
from web3.middleware import geth_poa_middleware


# Get device address list
def get_device_addresses():
    network.web3.middleware_onion.inject(geth_poa_middleware, layer=0)

    account = accounts.add(config["keys"]["admin_private_key"])
    group_key_management = GroupKeyManagement[-1]
    device_addresses_tuple = group_key_management.getDeviceAddresses(
        {"from": account, "required_confs": 0}
    )
    device_addresses_list = list(device_addresses_tuple)
    print(device_addresses_list)
    print(len(device_addresses_list))


def main():
    get_device_addresses()

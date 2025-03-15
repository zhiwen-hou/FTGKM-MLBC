from scripts.group_key_management.init import init_device_addresses
from scripts.contribution_storage.calculate_contribution_ratio import (
    init_reputation,
)
from web3.middleware import geth_poa_middleware
from brownie import network


def main():
    network.web3.middleware_onion.inject(geth_poa_middleware, layer=0)

    # Clear the device list and group key list in the contract
    init_device_addresses()

    # Clear the contribution value of each blockchain node
    init_reputation()

from scripts.contribution_storage.calculate_contribution_ratio import (
    init_reputation,
)
from brownie import network
from web3.middleware import geth_poa_middleware


def main():
    network.web3.middleware_onion.inject(geth_poa_middleware, layer=0)

    init_reputation()

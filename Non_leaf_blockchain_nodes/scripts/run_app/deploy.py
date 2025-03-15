from scripts.public_key_storage.deploy import deploy_public_key_storage
from scripts.public_key_storage.store import store_self_and_son
from scripts.contribution_storage.deploy import deploy_contribution_storage
from scripts.group_message_storage.deploy import deploy_group_message_storage
from web3.middleware import geth_poa_middleware
from brownie import network


def main():
    network.web3.middleware_onion.inject(geth_poa_middleware, layer=0)

    deploy_public_key_storage()

    store_self_and_son()

    deploy_contribution_storage()
    deploy_group_message_storage()


if __name__ == "__main__":
    main()

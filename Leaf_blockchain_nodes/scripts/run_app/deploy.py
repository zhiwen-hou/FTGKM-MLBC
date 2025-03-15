from scripts.public_key_storage.deploy import deploy_public_key_storage
from scripts.public_key_storage.store import store_self_and_parent_and_ca
from scripts.contribution_storage.deploy import deploy_contribution_storage
from scripts.group_key_management.deploy import deploy_group_key_management
from scripts.group_message_storage.deploy import deploy_group_message_storage
from scripts.message_rocord_storage.deploy import deploy_message_record_storage
from web3.middleware import geth_poa_middleware
from brownie import network


def main():
    network.web3.middleware_onion.inject(geth_poa_middleware, layer=0)

    # Deploy the contract
    deploy_public_key_storage()

    # Stores the address and public key of its own blockchain and parent blockchain
    store_self_and_parent_and_ca()

    deploy_contribution_storage()
    deploy_group_key_management()
    deploy_group_message_storage()
    deploy_message_record_storage()

    pass


if __name__ == "__main__":
    main()

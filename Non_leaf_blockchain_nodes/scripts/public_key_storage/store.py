from brownie import PublicKeyStorage, accounts, config
from scripts.configure_basic_parameters.sec_key_utils import my_get_public_key_bytes
from scripts.configure_basic_parameters.addresses_and_ips import get_addresses
from scripts.configure_basic_parameters.adjacent_chains import (
    get_adjacent_chain_id_by_name,
)


def store_address(chain_name="self"):
    public_key_storage = PublicKeyStorage[-1]
    account = accounts.add(config["keys"]["admin_private_key"])

    addresses = get_addresses(chain_name)
    if chain_name == "self":
        public_key_storage.storeSelfAddresses(addresses, {"from": account})
    if chain_name[:3] == "son":
        chain_id = get_adjacent_chain_id_by_name(chain_name)
        public_key_storage.storeSonAddresses(chain_id, addresses, {"from": account})


def store_public_key(chain_name="self"):
    public_key_storage = PublicKeyStorage[-1]
    account = accounts.add(config["keys"]["admin_private_key"])

    addresses = get_addresses(chain_name)
    i = 0
    for address in addresses:
        num = f"0{i}"
        i += 1
        if chain_name == "self":
            public_key_storage.storeSelfPublicKey(
                address,
                my_get_public_key_bytes(num),
                {"from": account, "required_confs": 0},
            )
        if chain_name[:3] == "son":
            chain_id = get_adjacent_chain_id_by_name(chain_name)
            public_key_storage.storeSonPublicKey(
                chain_id,
                address,
                my_get_public_key_bytes(num, chain_name),
                {"from": account, "required_confs": 0},
            )


def store_self_and_son():
    store_address()
    store_public_key()

    store_address("son1102")
    store_public_key(chain_name="son1102")

    store_address("son1103")
    store_public_key(chain_name="son1103")


def main():
    store_self_and_son()


if __name__ == "__main__":
    main()

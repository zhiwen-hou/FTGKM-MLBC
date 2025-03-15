# Store public information of blockchain and CA

from brownie import PublicKeyStorage, accounts, config
from scripts.configure_basic_parameters.sec_key_utils import my_get_public_key_bytes
from scripts.configure_basic_parameters.addresses_and_ips import get_addresses


def store_address(chain_name="self"):
    public_key_storage = PublicKeyStorage[-1]
    account = accounts.add(config["keys"]["admin_private_key"])

    addresses = get_addresses(chain_name)
    if chain_name == "self":
        public_key_storage.storeSelfAddresses(addresses, {"from": account})
    if chain_name == "parent":
        public_key_storage.storeParentAddresses(addresses, {"from": account})
    if chain_name == "ca":
        public_key_storage.storeCaAddresses(addresses, {"from": account})


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
        if chain_name == "parent":
            public_key_storage.storeParentPublicKey(
                address,
                my_get_public_key_bytes(num, chain_name),
                {"from": account, "required_confs": 0},
            )


def store_self_and_parent_and_ca():
    store_address()
    store_public_key()

    store_address("parent")
    store_public_key(chain_name="parent")

    store_address("ca")


def main():
    store_self_and_parent_and_ca()


if __name__ == "__main__":
    main()

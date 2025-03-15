from brownie import PublicKeyStorage, accounts, config
from scripts.configure_basic_parameters.addresses_and_ips import get_addresses
from scripts.configure_basic_parameters.adjacent_chains import (
    get_adjacent_chain_id_by_name,
)


def get_address(chain_name="self"):
    public_key_storage = PublicKeyStorage[-1]
    account = accounts.add(config["keys"]["admin_private_key"])

    if chain_name == "self":
        addresses = public_key_storage.getSelfAddresses(
            {"from": account, "required_confs": 0}
        )
        length = public_key_storage.getSelfLength(
            {"from": account, "required_confs": 0}
        )
    if chain_name[:3] == "son":
        chain_id = get_adjacent_chain_id_by_name(chain_name)
        addresses = public_key_storage.getSonAddresses(
            chain_id, {"from": account, "required_confs": 0}
        )
        length = public_key_storage.getSonLength(
            chain_id, {"from": account, "required_confs": 0}
        )

    print(f"{chain_name}_addresses={addresses}")
    print(f"{chain_name}_length={length}")


def get_public_key(chain_name="self"):
    public_key_storage = PublicKeyStorage[-1]
    account = accounts.add(config["keys"]["admin_private_key"])

    addresses = get_addresses(chain_name)
    i = 0
    for address in addresses:
        num = f"0{i}"
        i += 1

        if chain_name == "self":
            public_key = public_key_storage.getSelfPublicKey(
                address, {"from": account, "required_confs": 0}
            )
        if chain_name[:3] == "son":
            chain_id = get_adjacent_chain_id_by_name(chain_name)
            public_key = public_key_storage.getSonPublicKey(
                chain_id, address, {"from": account, "required_confs": 0}
            )
        print(f"public_key{num}={public_key}")


def main():
    get_address()
    get_public_key()
    get_address("son1102")
    get_public_key(chain_name="son1102")
    get_address("son1103")
    get_public_key(chain_name="son1103")


if __name__ == "__main__":
    main()

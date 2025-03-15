from brownie import PublicKeyStorage, accounts, config
from cryptography.hazmat.primitives import serialization
from secp256k1 import PublicKey

from scripts.configure_basic_parameters.addresses_and_ips import get_addresses


# Get the address list and length of the blockchain node from the contract
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
    if chain_name == "parent":
        addresses = public_key_storage.getParentAddresses(
            {"from": account, "required_confs": 0}
        )
        length = public_key_storage.getParentLength(
            {"from": account, "required_confs": 0}
        )
    if chain_name == "ca":
        addresses = public_key_storage.getCaAddresses(
            {"from": account, "required_confs": 0}
        )
        length = public_key_storage.getCaLength({"from": account, "required_confs": 0})

    print(f"{chain_name}_addresses={addresses}")
    print(f"{chain_name}_length={length}")


# Get the public key of the blockchain node from the contract
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
        if chain_name == "parent":
            public_key = public_key_storage.getParentPublicKey(
                address, {"from": account, "required_confs": 0}
            )
        print(f"public_key{num}={public_key}")


def main():
    get_address()
    get_public_key()
    get_address("parent")
    get_public_key(chain_name="parent")
    get_address("ca")


if __name__ == "__main__":
    main()

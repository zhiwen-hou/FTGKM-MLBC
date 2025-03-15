from brownie import PublicKeyStorage, accounts, config


def deploy_public_key_storage():
    account = accounts.add(config["keys"]["admin_private_key"])
    public_key_storage = PublicKeyStorage.deploy(
        config["blockchain_level"], {"from": account}
    )
    print("Public key storage contract has been deployed")
    return public_key_storage


def main():
    deploy_public_key_storage()


if __name__ == "__main__":
    main()

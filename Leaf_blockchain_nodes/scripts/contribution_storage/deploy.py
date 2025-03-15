from brownie import accounts, ContributionStorage, PublicKeyStorage, config


def deploy_contribution_storage():
    account = accounts.add(config["keys"]["admin_private_key"])
    contribution_storage = ContributionStorage.deploy(
        PublicKeyStorage[-1], {"from": account}
    )
    print("Contribution value storage contract has been deployed")
    return contribution_storage


def main():
    deploy_contribution_storage()


if __name__ == "__main__":
    main()

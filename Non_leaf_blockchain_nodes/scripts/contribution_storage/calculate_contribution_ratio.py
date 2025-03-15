from brownie import accounts, ContributionStorage, PublicKeyStorage, config, network
import datetime
from web3.middleware import geth_poa_middleware


def calculate_reputation_ratio():
    account = accounts.add(config["keys"]["admin_private_key"])
    contribution_storage = ContributionStorage[-1]
    public_key_storage = PublicKeyStorage[-1]

    self_addresses = public_key_storage.getSelfAddresses(
        {"from": account, "required_confs": 0}
    )
    reputations = []
    total_reputation = 0
    for self_address in self_addresses:
        reputation = contribution_storage.getReputationByAddress(
            self_address, {"from": account, "required_confs": 0}
        )
        reputations.append(reputation)
        total_reputation += reputation

    ratios = []

    for reputation in reputations:
        ratio = reputation / total_reputation
        ratios.append(ratio)

    return reputations, ratios


def init_reputation():
    account = accounts.add(config["keys"]["admin_private_key"])
    contribution_storage = ContributionStorage[-1]

    contribution_storage.initReputation({"from": account})


def settle_accounts():
    account = accounts.add(config["keys"]["admin_private_key"])
    contribution_storage = ContributionStorage[-1]

    ratios = calculate_reputation_ratio()
    init_reputation()

    price_per_second = 0.000003

    last_settle_time = contribution_storage.getLastSettleTime(
        {"from": account, "required_confs": 0}
    )
    timestamp = int(datetime.datetime.today().timestamp())

    total_reward = (timestamp - last_settle_time) * price_per_second
    rewards = []

    for ratio in ratios:
        reward = total_reward * ratio
        rewards.append(reward)

    return rewards


def main():
    network.web3.middleware_onion.inject(geth_poa_middleware, layer=0)

    reputations, ratios = calculate_reputation_ratio()
    reputations = [reputation / (10**6) for reputation in reputations]
    print(f"reputations={reputations}")
    print(f"ratios={ratios}")


if __name__ == "__main__":
    main()

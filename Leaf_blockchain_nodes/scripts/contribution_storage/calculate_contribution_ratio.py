# Node Contribution Value Calculation Tool

from brownie import accounts, ContributionStorage, config, network
from scripts.configure_basic_parameters.addresses_and_ips import get_addresses
from web3.middleware import geth_poa_middleware


def calculate_reputation_ratio():
    account = accounts.add(config["keys"]["admin_private_key"])
    contribution_storage = ContributionStorage[-1]

    self_addresses = get_addresses()
    reputations_matrix = []
    total_ratios = [0, 0, 0, 0, 0]
    for self_address in self_addresses:
        reputations = contribution_storage.getTotalReputationByAddress(
            self_address, {"from": account, "required_confs": 0}
        )
        reputations_list = list(reputations)
        reputations_matrix.append(reputations_list)

    for i in range(len(self_addresses)):
        for j in range(len(reputations_list)):
            total_ratios[j] += reputations_matrix[i][j]
            reputations_matrix[i][j] = reputations_matrix[i][j] / (10**6)

    # print("The reputation ratio of each server has been calculated")

    return total_ratios, reputations_matrix


def init_reputation():
    account = accounts.add(config["keys"]["admin_private_key"])
    contribution_storage = ContributionStorage[-1]

    contribution_storage.initReputation({"from": account})

    print("The reputation and contribution values ​​of all servers have been reset")


def main():
    network.web3.middleware_onion.inject(geth_poa_middleware, layer=0)

    total_ratios, reputations_matrix = calculate_reputation_ratio()
    print(f"total_ratios={total_ratios}")
    print(f"reputations_matrix={reputations_matrix}")


if __name__ == "__main__":
    main()

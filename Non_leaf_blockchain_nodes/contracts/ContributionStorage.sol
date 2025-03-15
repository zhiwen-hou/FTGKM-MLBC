// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.9.0;

import "./PublicKeyStorage.sol";

contract ContributionStorage {
    mapping(address => uint256) public addressToContribution;
    mapping(address => uint256) public addressToReputation;

    address[] public authorizedContractAddresses;

    uint256 public contributionSum = 0;
    uint256 constant PRECISION = 10 ** 6;
    uint256 constant DECIMALS = 10 ** 5;
    uint256 public smoothingCoefficient = 5 * DECIMALS;

    event MaliciousNodesFound(address malicious, uint256 reputation);

    uint256 public lastSettleTime;

    PublicKeyStorage public publicKeyStorage;

    constructor(address _publicKeyStorageAddress) {
        publicKeyStorage = PublicKeyStorage(_publicKeyStorageAddress);
        initReputation();
    }

    function getReputationByAddress(
        address _address
    ) public view returns (uint256) {
        return addressToReputation[_address];
    }

    function addContributionForAddress(
        address _address,
        uint256 _value
    ) public {
        addressToContribution[_address] =
            addressToContribution[_address] +
            _value;
        contributionSum = contributionSum + _value;
    }

    function initReputation() public {
        address[] memory selfAddresses = publicKeyStorage.getSelfAddresses();
        for (uint256 i = 0; i < selfAddresses.length; i++) {
            addressToReputation[selfAddresses[i]] = 10 * DECIMALS;
            addressToContribution[selfAddresses[i]] = 0;
        }
        contributionSum = 0;
    }

    // Update reputation
    function updateReputationByContribution() public {
        address[] memory selfAddresses = publicKeyStorage.getSelfAddresses();
        for (uint256 i = 0; i < selfAddresses.length; i++) {
            uint256 contributionRatio = (addressToContribution[
                selfAddresses[i]
            ] * PRECISION) / contributionSum;
            uint256 newReputation = (((PRECISION - smoothingCoefficient) *
                addressToReputation[selfAddresses[i]]) +
                smoothingCoefficient *
                contributionRatio *
                selfAddresses.length) / PRECISION;

            addressToReputation[selfAddresses[i]] = newReputation;

            addressToContribution[selfAddresses[i]] = 0;

            // If the reputation value is below the threshold,
            // the "MaliciousNodesFound" event is triggered
            if (addressToReputation[selfAddresses[i]] < 3 * DECIMALS) {
                emit MaliciousNodesFound(
                    selfAddresses[i],
                    addressToReputation[selfAddresses[i]]
                );
            }
        }
        contributionSum = 0;
    }

    function determineContributionSum() public view returns (bool) {
        uint256 selfLength = publicKeyStorage.getSelfLength();
        return contributionSum >= selfLength * 10;
    }
}

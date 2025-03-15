// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.9.0;

import "./PublicKeyStorage.sol";

contract ContributionStorage {
    mapping(address => uint256[]) public addressToContribution;
    mapping(address => uint256[]) public addressToReputation;

    uint256[] public contributionSum = new uint256[](5);
    uint256 constant PRECISION = 10 ** 6;
    uint256 constant DECIMALS = 10 ** 5;
    uint256 public smoothingCoefficient = 5 * DECIMALS;

    uint256[] initArray = [
        10 * DECIMALS,
        10 * DECIMALS,
        10 * DECIMALS,
        10 * DECIMALS,
        10 * DECIMALS
    ];

    // Used to identify whether it is a malicious node
    mapping(address => uint256) addressToMark;

    // Stores the hash value of the trigger condition
    mapping(bytes32 => bool) public triggerHashToBool;

    // Event triggered when a malicious node is detected
    event MaliciousNodesFound(address malicious, uint256 reputation);

    event GroupKeyReputationUpdated();
    event GroupMessageReputationUpdated();

    PublicKeyStorage public publicKeyStorage;

    // Set the node that deploys the contract as an administrator
    constructor(address _publicKeyStorageAddress) {
        publicKeyStorage = PublicKeyStorage(_publicKeyStorageAddress);
        initReputation();
    }

    function getTotalReputationByAddress(
        address _address
    ) public view returns (uint256[] memory) {
        return addressToReputation[_address];
    }

    function getReputationByAddressAndIndex(
        address _address,
        uint256 _index
    ) public view returns (uint256) {
        return addressToReputation[_address][_index];
    }

    function addContributionForAddress(
        address _address,
        uint256 _index,
        uint256 _value
    ) public {
        addressToContribution[_address][_index] =
            addressToContribution[_address][_index] +
            _value;
        contributionSum[_index] = contributionSum[_index] + _value;
    }

    function initReputation() public {
        address[] memory selfAddresses = publicKeyStorage.getSelfAddresses();
        for (uint256 i = 0; i < selfAddresses.length; i++) {
            uint256[] memory m_initArray = initArray;
            addressToReputation[selfAddresses[i]] = m_initArray;
            addressToContribution[selfAddresses[i]] = new uint256[](5);
            addressToMark[selfAddresses[i]] = 1;
        }
        contributionSum = new uint256[](5);
    }

    // Reputation update triggered by group key
    function updateReputationByGenerateGroupKey(
        address[] memory selfAddresses
    ) public returns (bool) {
        if (contributionSum[0] >= selfAddresses.length * 10) {
            for (uint256 i = 0; i < selfAddresses.length; i++) {
                uint256 contributionRatio = (addressToContribution[
                    selfAddresses[i]
                ][0] * PRECISION) / contributionSum[0];
                uint256 newReputation = (((PRECISION - smoothingCoefficient) *
                    addressToReputation[selfAddresses[i]][0]) +
                    smoothingCoefficient *
                    contributionRatio *
                    selfAddresses.length) / PRECISION;

                addressToReputation[selfAddresses[i]][0] =
                    newReputation *
                    addressToMark[selfAddresses[i]];

                // Clear contribution value after calculation
                addressToContribution[selfAddresses[i]][0] = 0;

                // If the reputation value is below the threshold,
                // the "MaliciousNodesFound" event is triggered
                if (addressToReputation[selfAddresses[i]][0] < 3 * DECIMALS) {
                    emit MaliciousNodesFound(
                        selfAddresses[i],
                        addressToReputation[selfAddresses[i]][0]
                    );
                }
            }
            // Clear contribution value after calculation
            contributionSum[0] = 0;

            return true;
        }
        return false;
    }

    function updateReputationByDistributeGroupKey(
        address[] memory selfAddresses
    ) public returns (bool) {
        if (contributionSum[1] >= selfAddresses.length * 10) {
            for (uint256 i = 0; i < selfAddresses.length; i++) {
                uint256 contributionRatio = (addressToContribution[
                    selfAddresses[i]
                ][1] * PRECISION) / contributionSum[1];
                uint256 newReputation = (((PRECISION - smoothingCoefficient) *
                    addressToReputation[selfAddresses[i]][1]) +
                    smoothingCoefficient *
                    contributionRatio *
                    selfAddresses.length) / PRECISION;

                addressToReputation[selfAddresses[i]][1] =
                    newReputation *
                    addressToMark[selfAddresses[i]];

                addressToContribution[selfAddresses[i]][1] = 0;

                if (addressToReputation[selfAddresses[i]][1] < 3 * DECIMALS) {
                    emit MaliciousNodesFound(
                        selfAddresses[i],
                        addressToReputation[selfAddresses[i]][1]
                    );
                }
            }
            contributionSum[1] = 0;

            return true;
        }
        return false;
    }

    function updateReputationByGroupKey() public {
        address[] memory selfAddresses = publicKeyStorage.getSelfAddresses();
        bool res1 = updateReputationByGenerateGroupKey(selfAddresses);
        bool res2 = updateReputationByDistributeGroupKey(selfAddresses);
        if (res1 || res2) {
            emit GroupKeyReputationUpdated();
        }
    }

    // Reputation update triggered by group messages
    function updateReputationByForwardToParent(
        address[] memory selfAddresses
    ) public returns (bool) {
        if (contributionSum[2] >= selfAddresses.length * 10) {
            for (uint256 i = 0; i < selfAddresses.length; i++) {
                uint256 contributionRatio = (addressToContribution[
                    selfAddresses[i]
                ][2] * PRECISION) / contributionSum[2];
                uint256 newReputation = (((PRECISION - smoothingCoefficient) *
                    addressToReputation[selfAddresses[i]][2]) +
                    smoothingCoefficient *
                    contributionRatio *
                    selfAddresses.length) / PRECISION;

                addressToReputation[selfAddresses[i]][2] =
                    newReputation *
                    addressToMark[selfAddresses[i]];

                addressToContribution[selfAddresses[i]][2] = 0;

                if (addressToReputation[selfAddresses[i]][2] < 3 * DECIMALS) {
                    emit MaliciousNodesFound(
                        selfAddresses[i],
                        addressToReputation[selfAddresses[i]][2]
                    );
                }
            }
            contributionSum[2] = 0;

            return true;
        }
        return false;
    }

    function updateReputationByForwardToDevice(
        address[] memory selfAddresses
    ) public returns (bool) {
        if (contributionSum[3] >= selfAddresses.length * 10) {
            for (uint256 i = 0; i < selfAddresses.length; i++) {
                uint256 contributionRatio = (addressToContribution[
                    selfAddresses[i]
                ][3] * PRECISION) / contributionSum[3];
                uint256 newReputation = (((PRECISION - smoothingCoefficient) *
                    addressToReputation[selfAddresses[i]][3]) +
                    smoothingCoefficient *
                    contributionRatio *
                    selfAddresses.length) / PRECISION;

                addressToReputation[selfAddresses[i]][3] =
                    newReputation *
                    addressToMark[selfAddresses[i]];

                addressToContribution[selfAddresses[i]][3] = 0;

                if (addressToReputation[selfAddresses[i]][3] < 3 * DECIMALS) {
                    emit MaliciousNodesFound(
                        selfAddresses[i],
                        addressToReputation[selfAddresses[i]][3]
                    );
                }
            }
            contributionSum[3] = 0;

            return true;
        }
        return false;
    }

    // Reputation update triggered by message logging request
    function updateReputationBySendRequest(
        address[] memory selfAddresses
    ) public returns (bool) {
        if (contributionSum[4] >= selfAddresses.length * 10) {
            for (uint256 i = 0; i < selfAddresses.length; i++) {
                uint256 contributionRatio = (addressToContribution[
                    selfAddresses[i]
                ][4] * PRECISION) / contributionSum[4];
                uint256 newReputation = (((PRECISION - smoothingCoefficient) *
                    addressToReputation[selfAddresses[i]][4]) +
                    smoothingCoefficient *
                    contributionRatio *
                    selfAddresses.length) / PRECISION;

                addressToReputation[selfAddresses[i]][4] =
                    newReputation *
                    addressToMark[selfAddresses[i]];

                addressToContribution[selfAddresses[i]][4] = 0;

                if (addressToReputation[selfAddresses[i]][4] < 3 * DECIMALS) {
                    emit MaliciousNodesFound(
                        selfAddresses[i],
                        addressToReputation[selfAddresses[i]][4]
                    );
                }
            }
            contributionSum[4] = 0;

            return true;
        }
        return false;
    }

    function updateReputationByGroupMessaage() public {
        address[] memory selfAddresses = publicKeyStorage.getSelfAddresses();
        bool res1 = updateReputationByForwardToParent(selfAddresses);
        bool res2 = updateReputationByForwardToDevice(selfAddresses);
        bool res3 = updateReputationBySendRequest(selfAddresses);

        if (res1 || res2 || res3) {
            emit GroupMessageReputationUpdated();
        }
    }

    function setAddressToMark(address _address) public {
        addressToMark[_address] = 0;
    }
}

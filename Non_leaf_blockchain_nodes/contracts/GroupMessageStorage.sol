// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.9.0;

import "./PublicKeyStorage.sol";
import "./ContributionStorage.sol";

contract GroupMessageStorage {
    struct SignedMessage {
        bytes32 msgh;
        bytes32 r;
        bytes32 s;
        uint8 v;
        bytes signature;
    }

    mapping(uint256 => mapping(bytes32 => address[]))
        public grpMesgHashToCountsigners;

    uint256 public triggerThreshold = 5000;
    uint256 public triggeringConditions = 100;

    PublicKeyStorage public publicKeyStorage;
    ContributionStorage public contributionStorage;

    event ReputationUpdated();

    uint256 public defaultTimeout;

    constructor(
        address _publicKeyStorageAddress,
        address _contributionStorageAddress,
        uint256 _defaultTimeout,
        uint256 _triggerThreshold,
        uint256 _triggeringConditions
    ) {
        publicKeyStorage = PublicKeyStorage(_publicKeyStorageAddress);
        contributionStorage = ContributionStorage(_contributionStorageAddress);
        defaultTimeout = _defaultTimeout;
        triggerThreshold = _triggerThreshold;
        triggeringConditions = _triggeringConditions;
    }

    function setTriggerThresholdAndConditions(
        uint256 _triggerThreshold,
        uint256 _triggeringConditions
    ) public {
        triggerThreshold = _triggerThreshold;
        triggeringConditions = _triggeringConditions;
    }

    function ecr(
        SignedMessage memory sign
    ) public pure returns (address sender) {
        return ecrecover(sign.msgh, sign.v, sign.r, sign.s);
    }

    // Determine whether a node has returned a confirmation signature
    // to prevent the same node from signing the same hash repeatedly
    function countersignExists(
        uint256 _adjacentChainId,
        bytes32 _sendMessageHash,
        address _countersigner
    ) public view returns (bool) {
        address[] memory countersigners = grpMesgHashToCountsigners[
            _adjacentChainId
        ][_sendMessageHash];
        for (uint256 i = 0; i < countersigners.length; i++) {
            if (_countersigner == countersigners[i]) {
                return true;
            }
        }
        return false;
    }

    // Convert bytes32 data to uint256 data
    function bytes32ToUint256(bytes32 data) public pure returns (uint256) {
        return uint256(data);
    }

    function storeGroupMessageHashCountersign(
        uint256 _messageLevel,
        uint256 _timestamp,
        bytes32 _groupMessageHash,
        uint256 _senderChainId,
        SignedMessage memory _senderSign,
        SignedMessage memory _selfSign,
        uint256 _adjacentChainId,
        SignedMessage memory _adjacentCounterSign
    ) public {
        bytes32 sendMessageHash = keccak256(
            abi.encodePacked(_messageLevel, _timestamp, _groupMessageHash)
        );

        require(
            _messageLevel <= publicKeyStorage.getBlockchianLevel(),
            "There is incorrect messageLevel"
        );

        require(
            block.timestamp < _timestamp ||
                block.timestamp - _timestamp < defaultTimeout,
            "There is incorrect timestamp"
        );

        // The source blockchain and the recipient blockchain must not be equal
        require(
            _senderChainId != _adjacentChainId,
            "senderChainId and adjacentChainId are the same"
        );

        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        bytes32 requireMessageHash = keccak256(
            abi.encodePacked(prefix, sendMessageHash)
        );
        require(
            keccak256(abi.encodePacked(requireMessageHash)) ==
                keccak256(abi.encodePacked(_senderSign.msgh)) &&
                keccak256(abi.encodePacked(requireMessageHash)) ==
                keccak256(abi.encodePacked(_selfSign.msgh)),
            "There are incorrect sendMessageHash"
        );

        // Verify whether the signature of the message source is correct, that is,
        // verify whether the message source is in the hash table
        address signer = ecr(_senderSign);
        address[] memory adjacentAddresses = publicKeyStorage.getSonAddresses(
            _senderChainId
        );
        uint256 hashUint256 = bytes32ToUint256(sendMessageHash);
        uint256 startIndex = hashUint256 % adjacentAddresses.length;
        bool verifySigner = false;
        for (uint256 i = 0; i < (adjacentAddresses.length - 1) / 3 + 1; i++) {
            if (
                signer ==
                adjacentAddresses[(startIndex + i) % adjacentAddresses.length]
            ) {
                verifySigner = true;
                break;
            }
        }
        require(verifySigner, "The senderSigner is incorrect");

        // Verify whether the signature of its own blockchain is correct,
        // that is, verify whether the signer is in the hash table
        signer = ecr(_selfSign);
        address[] memory selfAddresses = publicKeyStorage.getSelfAddresses();
        startIndex = hashUint256 % selfAddresses.length;
        verifySigner = false;
        for (uint256 i = 0; i < (selfAddresses.length - 1) / 3 + 1; i++) {
            if (
                signer == selfAddresses[(startIndex + i) % selfAddresses.length]
            ) {
                verifySigner = true;
                break;
            }
        }
        require(verifySigner, "The selfSigner is incorrect");

        bytes32 selfSignHash = keccak256(abi.encodePacked(_selfSign.signature));
        requireMessageHash = keccak256(abi.encodePacked(prefix, selfSignHash));
        require(
            keccak256(abi.encodePacked(requireMessageHash)) ==
                keccak256(abi.encodePacked(_adjacentCounterSign.msgh)),
            "There are incorrect selfSignHash"
        );

        // Verify whether the returned signature of the receiving blockchain is correct,
        // that is, verify whether the signer is in the hash table
        signer = ecr(_adjacentCounterSign);
        adjacentAddresses = publicKeyStorage.getSonAddresses(_adjacentChainId);
        startIndex = hashUint256 % adjacentAddresses.length;
        verifySigner = false;
        for (uint256 i = 0; i < (adjacentAddresses.length - 1) / 3 + 1; i++) {
            if (
                signer ==
                adjacentAddresses[(startIndex + i) % adjacentAddresses.length]
            ) {
                verifySigner = true;
                break;
            }
        }
        require(verifySigner, "The adjacentSigner is incorrect");

        require(
            !countersignExists(_adjacentChainId, sendMessageHash, signer),
            "Countersigner already exists"
        );

        grpMesgHashToCountsigners[_adjacentChainId][sendMessageHash].push(
            signer
        );

        contributionStorage.addContributionForAddress(msg.sender, 6);

        if (
            hashUint256 % triggerThreshold < triggeringConditions &&
            grpMesgHashToCountsigners[_adjacentChainId][sendMessageHash]
                .length ==
            1 &&
            contributionStorage.determineContributionSum()
        ) {
            contributionStorage.updateReputationByContribution();
            emit ReputationUpdated();
        }
    }
}

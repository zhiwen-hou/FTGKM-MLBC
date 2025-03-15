// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.9.0;

import "./PublicKeyStorage.sol";
import "./GroupKeyManagement.sol";
import "./ContributionStorage.sol";

contract GroupMessageStorage {
    struct SignedMessage {
        bytes32 msgh;
        bytes32 r;
        bytes32 s;
        uint8 v;
        bytes signature;
    }

    struct DeviceParameters {
        uint256 messageLevel;
        uint256 timestamp;
        bytes32 groupMessageHash;
        SignedMessage senderSign;
        SignedMessage selfSign;
        SignedMessage adjacentCounterSign;
    }

    struct ParentParameters {
        uint256 messageLevel;
        uint256 timestamp;
        bytes32 groupMessageHash;
        SignedMessage senderSign;
    }

    // Used to store countsigners for group messages
    mapping(bytes32 => address[]) public grpMesgHashToCountsigners;
    // Used to store the forwarder who forwarded the group message to the parent blockchain
    mapping(bytes32 => bool) public grpMesgHashToBool;

    uint256 public triggerThreshold = 5000;
    uint256 public triggeringConditions = 100;

    PublicKeyStorage public publicKeyStorage;
    GroupKeyManagement public groupKeyManagement;
    ContributionStorage public contributionStorage;

    uint256 public defaultTimeout;

    constructor(
        address _publicKeyStorageAddress,
        address _groupKeyManagementAddress,
        address _contributionStorageAddress,
        uint256 _defaultTimeout,
        uint256 _triggerThreshold,
        uint256 _triggeringConditions
    ) {
        publicKeyStorage = PublicKeyStorage(_publicKeyStorageAddress);
        groupKeyManagement = GroupKeyManagement(_groupKeyManagementAddress);
        contributionStorage = ContributionStorage(_contributionStorageAddress);
        defaultTimeout = _defaultTimeout;
        triggerThreshold = _triggerThreshold;
        triggeringConditions = _triggeringConditions;
    }

    // Only administrators can set the contract address with permissions
    function setTriggerThreshold(
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

    // Determine whether a node has returned a countersign to prevent
    // the same node from signing the same hash repeatedly
    function countersignExists(
        bytes32 _sendMessageHash,
        address _countersigner
    ) public view returns (bool) {
        address[] memory countersigners = grpMesgHashToCountsigners[
            _sendMessageHash
        ];
        for (uint256 i = 0; i < countersigners.length; i++) {
            if (_countersigner == countersigners[i]) {
                return true;
            }
        }
        return false;
    }

    // Stores confirmation signatures of group messages forwarded to the parent blockchain
    function storeGroupMessageHashCountersignTest(
        DeviceParameters[] memory _deviceParametersArray
    ) public {
        for (uint256 k = 0; k < _deviceParametersArray.length; k++) {
            // Calculate message hash
            bytes32 sendMessageHash = keccak256(
                abi.encodePacked(
                    _deviceParametersArray[k].messageLevel,
                    _deviceParametersArray[k].timestamp,
                    _deviceParametersArray[k].groupMessageHash
                )
            );

            // Check that the message hierarchy is correct
            require(
                _deviceParametersArray[k].messageLevel <=
                    publicKeyStorage.getBlockchianLevel(),
                "There is incorrect messageLevel"
            );

            require(
                block.timestamp < _deviceParametersArray[k].timestamp ||
                    block.timestamp - _deviceParametersArray[k].timestamp <
                    defaultTimeout,
                "There is incorrect timestamp"
            );

            // Verify that the hash of the message is correct
            bytes memory prefix = "\x19Ethereum Signed Message:\n32";
            bytes32 requireMessageHash = keccak256(
                abi.encodePacked(prefix, sendMessageHash)
            );
            require(
                keccak256(abi.encodePacked(requireMessageHash)) ==
                    keccak256(
                        abi.encodePacked(
                            _deviceParametersArray[k].senderSign.msgh
                        )
                    ) &&
                    keccak256(abi.encodePacked(requireMessageHash)) ==
                    keccak256(
                        abi.encodePacked(
                            _deviceParametersArray[k].selfSign.msgh
                        )
                    ),
                "There are incorrect sendMessageHash"
            );

            // Verify whether the device's signature is correct,
            // that is, whether the device is still in the group
            address deviceSigner = ecr(_deviceParametersArray[k].senderSign);
            require(
                groupKeyManagement.checkDeviceAddress(deviceSigner),
                "There are incorrect deviceSigner"
            );

            // Verify whether the signature of its own blockchain is correct
            // Verify whether the message forwarder is in the hash table
            address signer01 = ecr(_deviceParametersArray[k].selfSign);
            address[] memory addressesArr01 = publicKeyStorage
                .getSelfAddresses();
            uint256 selfRequireNum = (addressesArr01.length - 1) / 3 + 1;
            // uint256 hashUint256 = uint256(sendMessageHash);
            uint256 startIndex = uint256(sendMessageHash) %
                addressesArr01.length;
            bool verifySigner = false;
            for (uint256 i = 0; i < selfRequireNum; i++) {
                if (
                    signer01 ==
                    addressesArr01[(startIndex + i) % addressesArr01.length]
                ) {
                    verifySigner = true;
                    break;
                }
            }
            require(verifySigner, "The selfSigner is incorrect");

            // Verify that the hash of the message is correct
            bytes32 selfSignHash = keccak256(
                abi.encodePacked(_deviceParametersArray[k].selfSign.signature)
            );
            requireMessageHash = keccak256(
                abi.encodePacked(prefix, selfSignHash)
            );
            require(
                keccak256(abi.encodePacked(requireMessageHash)) ==
                    keccak256(
                        abi.encodePacked(
                            _deviceParametersArray[k].adjacentCounterSign.msgh
                        )
                    ),
                "There are incorrect selfSignHash"
            );

            // Verify that the return signature of the parent blockchain is correct
            // Verify the message recipient of the parent blockchain
            // Verify that the signer is in the hash table
            signer01 = ecr(_deviceParametersArray[k].adjacentCounterSign);
            addressesArr01 = publicKeyStorage.getParentAddresses();
            uint256 parentRequireNum = (addressesArr01.length - 1) / 3 + 1;
            startIndex = uint256(sendMessageHash) % addressesArr01.length;
            verifySigner = false;
            for (uint256 i = 0; i < parentRequireNum; i++) {
                if (
                    signer01 ==
                    addressesArr01[(startIndex + i) % addressesArr01.length]
                ) {
                    verifySigner = true;
                    break;
                }
            }
            require(verifySigner, "The parentSigner is incorrect");

            // Determine whether countersign already exists
            require(
                !countersignExists(sendMessageHash, signer01),
                "Countersigner already exists"
            );

            // Storage confirms the signer and sender
            grpMesgHashToCountsigners[sendMessageHash].push(signer01);
            grpMesgHashToBool[sendMessageHash] = true;

            // Increase the contribution value of the forwarder
            contributionStorage.addContributionForAddress(msg.sender, 2, 1);

            if (
                uint256(sendMessageHash) % triggerThreshold <
                triggeringConditions &&
                grpMesgHashToCountsigners[sendMessageHash].length == 1
            ) {
                contributionStorage.updateReputationByGroupMessaage();
            }
        }
    }

    // Stores confirmation signatures for group messages forwarded to a group of devices
    function storeGroupMessageHashFromParentTest(
        ParentParameters[] memory _parentParametersArray
    ) public {
        for (uint256 k = 0; k < _parentParametersArray.length; k++) {
            bytes32 sendMessageHash = keccak256(
                abi.encodePacked(
                    _parentParametersArray[k].messageLevel,
                    _parentParametersArray[k].timestamp,
                    _parentParametersArray[k].groupMessageHash
                )
            );

            require(
                _parentParametersArray[k].messageLevel <=
                    publicKeyStorage.getBlockchianLevel(),
                "There is incorrect messageLevel"
            );

            address[] memory addressesArr01 = publicKeyStorage
                .getSelfAddresses();
            uint256 selfRequireNum = (addressesArr01.length - 1) / 3 + 1;
            uint256 hashUint256 = uint256(sendMessageHash);
            uint256 startIndex = hashUint256 % addressesArr01.length;
            bool verifySigner = false;
            for (uint256 i = 0; i < selfRequireNum; i++) {
                if (
                    msg.sender ==
                    addressesArr01[(startIndex + i) % addressesArr01.length]
                ) {
                    verifySigner = true;
                    break;
                }
            }
            require(verifySigner, "The selfSigner is incorrect");

            require(
                grpMesgHashToBool[sendMessageHash] == false,
                "The number of forwarder are sufficient"
            );

            require(
                block.timestamp < _parentParametersArray[k].timestamp ||
                    block.timestamp - _parentParametersArray[k].timestamp <
                    defaultTimeout,
                "There is incorrect timestamp"
            );

            bytes memory prefix = "\x19Ethereum Signed Message:\n32";
            bytes32 requireMessageHash = keccak256(
                abi.encodePacked(prefix, sendMessageHash)
            );
            require(
                keccak256(abi.encodePacked(requireMessageHash)) ==
                    keccak256(
                        abi.encodePacked(
                            _parentParametersArray[k].senderSign.msgh
                        )
                    ),
                "There are incorrect sendMessageHash"
            );

            address parentSigner = ecr(_parentParametersArray[k].senderSign);
            addressesArr01 = publicKeyStorage.getParentAddresses();
            uint256 parentRequireNum = (addressesArr01.length - 1) / 3 + 1;
            startIndex = hashUint256 % addressesArr01.length;
            verifySigner = false;
            for (uint256 i = 0; i < parentRequireNum; i++) {
                if (
                    parentSigner ==
                    addressesArr01[(startIndex + i) % addressesArr01.length]
                ) {
                    verifySigner = true;
                    break;
                }
            }
            require(verifySigner, "The msg.sender is incorrect");

            // Storage Submit Transaction
            grpMesgHashToBool[sendMessageHash] = true;

            contributionStorage.addContributionForAddress(msg.sender, 3, 1);

            if (hashUint256 % triggerThreshold < triggeringConditions) {
                contributionStorage.updateReputationByGroupMessaage();
            }
        }
    }

    // Determine whether a message exists
    function recordMessageHashIsExist(
        bytes32 _recordMessageHash
    ) public view returns (bool) {
        return grpMesgHashToBool[_recordMessageHash];
    }
}

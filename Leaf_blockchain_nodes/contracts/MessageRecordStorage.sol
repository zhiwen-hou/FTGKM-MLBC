// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.9.0;

import "./PublicKeyStorage.sol";
import "./GroupKeyManagement.sol";
import "./GroupMessageStorage.sol";
// import "./VerifySignature.sol";
import "./ContributionStorage.sol";

contract MessageRecordStorage {
    struct SignedMessage {
        bytes32 msgh;
        bytes32 r;
        bytes32 s;
        uint8 v;
        bytes signature;
    }

    // Used to store confirmation signature sets
    mapping(bytes32 => address[]) public triggerHashToCountersigners;

    // Message recording interval/message recording length, i.e. contribution value base
    uint256 public contributionBase = 1;

    PublicKeyStorage public publicKeyStorage;
    GroupKeyManagement public groupKeyManagement;
    GroupMessageStorage public groupMessageStorage;
    ContributionStorage public contributionStorage;

    constructor(
        address _publicKeyStorageAddress,
        address _groupKeyManagementAddress,
        address _groupMessageStorageAddress,
        address _contributionStorageAddress
    ) {
        publicKeyStorage = PublicKeyStorage(_publicKeyStorageAddress);
        groupKeyManagement = GroupKeyManagement(_groupKeyManagementAddress);
        groupMessageStorage = GroupMessageStorage(_groupMessageStorageAddress);
        contributionStorage = ContributionStorage(_contributionStorageAddress);
    }

    function setTriggerThreshold(uint256 _contributionBase) public {
        contributionBase = _contributionBase;
    }

    function ecr(
        SignedMessage memory sign
    ) public pure returns (address sender) {
        return ecrecover(sign.msgh, sign.v, sign.r, sign.s);
    }

    function verifySendMessageHash(
        bytes memory _triggerHashSign,
        bytes32 _countersignHash,
        bytes32[] memory _recordHashList,
        address[] memory _signerList
    ) public pure returns (bool) {
        bytes memory forEncode = abi.encodePacked(_signerList[0]);
        for (uint256 i = 1; i < _signerList.length; i++) {
            forEncode = abi.encodePacked(forEncode, _signerList[i]);
        }
        // signerListHash
        bytes32 signerListHash = keccak256(forEncode);

        forEncode = abi.encodePacked(_recordHashList[0]);
        for (uint256 i = 1; i < _recordHashList.length; i++) {
            forEncode = abi.encodePacked(forEncode, _recordHashList[i]);
        }
        // recordHashListHash
        bytes32 recordHashListHash = keccak256(forEncode);

        //sendMessageHash
        bytes32 sendMessageHash = keccak256(
            abi.encodePacked(
                keccak256(abi.encodePacked(_triggerHashSign)),
                recordHashListHash,
                signerListHash
            )
        );

        // prefix
        forEncode = "\x19Ethereum Signed Message:\n32";
        // requireMessageHash
        sendMessageHash = keccak256(
            abi.encodePacked(forEncode, sendMessageHash)
        );

        if (
            keccak256(abi.encodePacked(sendMessageHash)) ==
            keccak256(abi.encodePacked(_countersignHash))
        ) {
            return true;
        }
        return false;
    }

    function storeDeviceRecord(
        bytes32 _triggerHash,
        uint256 _blockTimestamp,
        SignedMessage memory _triggerHashSign,
        SignedMessage memory _deviceCounertsign,
        bytes32[] memory _recordHashList,
        address[] memory _signerList
    ) public {
        bytes32 sendMessageHash = keccak256(
            abi.encodePacked(_blockTimestamp, _triggerHash)
        );

        // Determine whether triggerNum exists
        require(
            groupKeyManagement.recordMessageHashIsExist(_triggerHash) ||
                groupMessageStorage.recordMessageHashIsExist(_triggerHash),
            "triggerNum is not exist"
        );

        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        sendMessageHash = keccak256(abi.encodePacked(prefix, sendMessageHash));
        require(
            keccak256(abi.encodePacked(sendMessageHash)) ==
                keccak256(abi.encodePacked(_triggerHashSign.msgh)),
            "There are incorrect sendMessageHash"
        );

        address selfSigner = ecr(_triggerHashSign);
        address[] memory addressArray = publicKeyStorage.getSelfAddresses();
        uint256 selfRequireNum = (addressArray.length - 1) / 3 + 1;
        uint256 startIndex = uint256(_triggerHash) % addressArray.length;
        bool verifySigner = false;
        for (uint256 i = 0; i < selfRequireNum; i++) {
            if (
                selfSigner ==
                addressArray[(startIndex + i) % addressArray.length]
            ) {
                verifySigner = true;
                break;
            }
        }
        require(verifySigner, "The selfSigner is incorrect");

        // Verify that the hash of the reply message is correct
        require(
            verifySendMessageHash(
                _triggerHashSign.signature,
                _deviceCounertsign.msgh,
                _recordHashList,
                _signerList
            ),
            "There are incorrect deviceCounertsign"
        );

        // Determine whether the signer is correct
        address countersigner = ecr(_deviceCounertsign);
        addressArray = groupKeyManagement.getDeviceAddresses();
        startIndex = uint256(_triggerHash) % addressArray.length;
        verifySigner = false;
        for (uint256 i = 0; i < addressArray.length; i++) {
            if (
                countersigner ==
                addressArray[
                    ((startIndex % addressArray.length) + i) %
                        addressArray.length
                ]
            ) {
                verifySigner = true;
                break;
            }
        }
        require(verifySigner, "There are incorrect deviceCountersigner");

        require(
            !countersignExists(_triggerHash, countersigner),
            "Countersign already exists"
        );

        // Storing signatures and senders
        triggerHashToCountersigners[_triggerHash].push(countersigner);

        contributionBase = addressArray.length / (selfRequireNum * 2);

        // Increase the contribution value of the server that sends the request message record
        contributionStorage.addContributionForAddress(msg.sender, 4, 1);

        // Increase the contribution value of the signer in the message record
        for (uint256 i = 0; i < _signerList.length; i++) {
            if (
                groupKeyManagement.recordMessageHashIsExist(_recordHashList[i])
            ) {
                contributionStorage.addContributionForAddress(
                    _signerList[i],
                    1,
                    contributionBase
                );
            } else if (
                groupMessageStorage.recordMessageHashIsExist(_recordHashList[i])
            ) {
                contributionStorage.addContributionForAddress(
                    _signerList[i],
                    3,
                    contributionBase
                );
            } else {
                contributionStorage.setAddressToMark(_signerList[i]);
            }
        }
    }

    // Determine whether a device has returned a confirmation signature
    // to prevent the same node from signing the same merged hash repeatedly
    function countersignExists(
        bytes32 _triggerHash,
        address _countersigner
    ) public view returns (bool) {
        address[]
            memory triggerHashCountersigners = triggerHashToCountersigners[
                _triggerHash
            ];
        for (uint256 i = 0; i < triggerHashCountersigners.length; i++) {
            if (_countersigner == triggerHashCountersigners[i]) {
                return true;
            }
        }
        return false;
    }
}

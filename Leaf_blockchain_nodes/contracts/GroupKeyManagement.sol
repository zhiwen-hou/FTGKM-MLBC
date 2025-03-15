// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.9.0;

import "./PublicKeyStorage.sol";
import "./ContributionStorage.sol";

contract GroupKeyManagement {
    // Message signature structure
    struct SignedMessage {
        bytes32 msgh;
        bytes32 r;
        bytes32 s;
        uint8 v;
        bytes signature;
    }

    // Certificate structure
    struct Cert {
        uint256 deviceId;
        string deviceIp;
        bytes secPublicKey;
        address deviceAddress;
        uint256 caId;
        uint256 notValidBefore;
        uint256 notValidAfter;
        bytes32 certHash;
        SignedMessage certSign;
    }

    // Device information structure
    struct DeviceInfo {
        bool deviceStatus;
        string deviceIp;
        bytes deviceSecPublicKey;
        uint256 notValidAfter;
    }

    address[] public deviceAddresses;
    string[] public deviceIps;
    mapping(address => DeviceInfo) public addressToDeviceInfo;

    mapping(bytes32 => mapping(address => bytes))
        public groupKeyHashToAddressToGroupKey;
    mapping(bytes32 => address) public groupKeyHashToGenerator;

    // Used to determine whether the group key has been stored
    mapping(bytes32 => bool) public groupKeyHashToBool;

    // Used to determine whether the record in the message log exists
    mapping(bytes32 => bool) public recordMessageHashToBool;

    // Conditions that trigger the RequestRecord event
    uint256 public triggerThreshold = 5000;
    uint256 public triggeringConditions = 100;

    bytes32[3] public latestGroupKeyHashs;

    PublicKeyStorage public publicKeyStorage;
    ContributionStorage public contributionStorage;

    uint256 public defaultTimeout;

    // Device list and group key update complete events
    event GroupKeyUpdated(bytes32 groupKeyHash, uint256 updatedTime);

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

    // Only administrators can set the contract address with permissions
    function setTriggerThreshold(
        uint256 _triggerThreshold,
        uint256 _triggeringConditions
    ) public {
        triggerThreshold = _triggerThreshold;
        triggeringConditions = _triggeringConditions;
    }

    // Determine whether the group key has been used
    function groupKeyHashIsExist(
        bytes32 _groupKeyHash
    ) public view returns (bool) {
        return groupKeyHashToBool[_groupKeyHash];
    }

    // Checks if the given address belongs to a group
    function checkDeviceAddress(address _address) public view returns (bool) {
        return addressToDeviceInfo[_address].deviceStatus;
    }

    // Verify certificates and device signatures
    // verify signatures of non-blockchain nodes
    function ecr(
        SignedMessage memory sign
    ) public pure returns (address sender) {
        return ecrecover(sign.msgh, sign.v, sign.r, sign.s);
    }

    // Verify that the certificate hash in the certificate is correct
    function verifyCertHash(Cert memory _cert) public pure returns (bool) {
        bytes32 certHash = keccak256(
            abi.encodePacked(
                _cert.deviceId,
                _cert.deviceIp,
                _cert.secPublicKey,
                _cert.deviceAddress,
                _cert.caId,
                _cert.notValidBefore,
                _cert.notValidAfter
            )
        );

        return
            keccak256(abi.encodePacked(certHash)) ==
            keccak256(abi.encodePacked(_cert.certHash));
    }

    // Verify that the hash of the request message is correct
    function verifySendMessageHash(
        uint256 _timestamp,
        Cert memory _cert,
        SignedMessage memory _messageSign
    ) public pure returns (bool, bytes32) {
        bytes32 certSignHash = keccak256(
            abi.encodePacked(
                _cert.certSign.msgh,
                _cert.certSign.r,
                _cert.certSign.s,
                _cert.certSign.v,
                _cert.certSign.signature
            )
        );
        bytes32 certMessageHash = keccak256(
            abi.encodePacked(
                _cert.deviceId,
                _cert.deviceIp,
                _cert.secPublicKey,
                _cert.deviceAddress,
                _cert.caId,
                _cert.notValidBefore,
                _cert.notValidAfter,
                _cert.certHash,
                certSignHash
            )
        );
        bytes32 sendMessageHash = keccak256(
            abi.encodePacked(_timestamp, certMessageHash)
        );
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        bytes32 requireMessageHash = keccak256(
            abi.encodePacked(prefix, sendMessageHash)
        );

        bool vertfyResulf = (keccak256(abi.encodePacked(requireMessageHash)) ==
            keccak256(abi.encodePacked(_messageSign.msgh)));

        return (vertfyResulf, sendMessageHash);
    }

    // Process the join request and trigger the GroupKeyUpdated event
    function deviceJoinGroup(
        string memory _messageType,
        uint256 _timestamp,
        Cert memory _cert,
        SignedMessage memory _messageSign,
        bytes32 _groupKeyHash,
        address[] memory _selfChainAddresses,
        bytes[] memory _encryptedGroupKeys
    ) public {
        // Verify that the message type is correct
        require(
            keccak256(abi.encodePacked(_messageType)) ==
                keccak256(abi.encodePacked("join group")),
            "MessageType is incorrect"
        );

        // Requires that the group key has not been stored
        require(
            !groupKeyHashToBool[_groupKeyHash],
            "The groupKeyHash is exist"
        );

        // Verify that the timestamp meets the requirements
        require(
            block.timestamp < _timestamp ||
                block.timestamp - _timestamp < defaultTimeout,
            "Timestamp does not meet requirements"
        );

        // Verify that the certificate hash is correct
        require(verifyCertHash(_cert), "There are incorrect certHash");

        // Verify that the certificate is correct
        address signer = ecr(_cert.certSign);
        require(
            publicKeyStorage.checkCaAddress(signer),
            "There are incorrect certSign"
        );

        // Verify that the certificate validity period meets the requirements
        require(
            block.timestamp > _cert.notValidBefore &&
                block.timestamp < _cert.notValidAfter,
            "Cert validity period error"
        );

        // Verify that the hash of the request message is correct
        (bool verifyResult, bytes32 sendMessageHash) = verifySendMessageHash(
            _timestamp,
            _cert,
            _messageSign
        );
        require(verifyResult, "There are incorrect sendMessageHash");

        // Verify that the transaction sender is in the hash table
        address[] memory selfAddressesArr = publicKeyStorage.getSelfAddresses();
        uint256 requireNum = (selfAddressesArr.length - 1) / 3 + 1;
        uint256 startIndex = uint256(sendMessageHash) % selfAddressesArr.length;
        verifyResult = false;
        for (uint256 i = 0; i < requireNum; i++) {
            if (
                msg.sender ==
                selfAddressesArr[(startIndex + i) % selfAddressesArr.length]
            ) {
                verifyResult = true;
                break;
            }
        }
        require(verifyResult, "The msg.sender is incorrect");

        // Verify that the signature of the request message is correct
        signer = ecr(_messageSign);
        require(
            signer == _cert.deviceAddress,
            "There are incorrect requestMessageSign"
        );

        // Requires the device to be in the Away state
        require(
            addressToDeviceInfo[_cert.deviceAddress].deviceStatus == false,
            "The device has joined the group"
        );

        // Store or update device information
        deviceAddresses.push(_cert.deviceAddress);
        deviceIps.push(_cert.deviceIp);
        DeviceInfo memory deviceInfo = DeviceInfo(
            true,
            _cert.deviceIp,
            _cert.secPublicKey,
            _cert.notValidAfter
        );
        addressToDeviceInfo[_cert.deviceAddress] = deviceInfo;

        // Store and update group key information
        for (uint256 i = 0; i < _selfChainAddresses.length; i++) {
            groupKeyHashToAddressToGroupKey[_groupKeyHash][
                _selfChainAddresses[i]
            ] = _encryptedGroupKeys[i];
        }
        groupKeyHashToGenerator[_groupKeyHash] = msg.sender;
        latestGroupKeyHashs[2] = latestGroupKeyHashs[1];
        latestGroupKeyHashs[1] = latestGroupKeyHashs[0];
        latestGroupKeyHashs[0] = _groupKeyHash;

        bytes32 recordMessageHash = keccak256(
            abi.encodePacked(block.timestamp, _groupKeyHash)
        );
        recordMessageHashToBool[recordMessageHash] = true;

        // Increase the contribution value of key generators
        contributionStorage.addContributionForAddress(msg.sender, 0, 1);

        // Triggering the GroupKeyUpdated event
        emit GroupKeyUpdated(_groupKeyHash, block.timestamp);

        // Determine whether it is necessary to trigger an event
        // to send a request message to the device
        // or directly update the reputation value
        if (
            uint256(sendMessageHash) % triggerThreshold < triggeringConditions
        ) {
            recordMessageHashToBool[sendMessageHash] = true;
            contributionStorage.updateReputationByGroupKey();
        }
    }

    // Get the latest group key hash
    function getLatestGroupKeyHashs() public view returns (bytes32[3] memory) {
        return latestGroupKeyHashs;
    }

    // Get the group key and the group key generator based on the group key hash and address
    function getEncryptedGroupKey(
        bytes32 _groupKeyHash,
        address _address
    ) public view returns (bytes memory, bytes memory) {
        bytes memory generatorPublicKey = publicKeyStorage.getSelfPublicKey(
            groupKeyHashToGenerator[_groupKeyHash]
        );
        return (
            generatorPublicKey,
            groupKeyHashToAddressToGroupKey[_groupKeyHash][_address]
        );
    }

    // Get the address list of devices in the group
    function getDeviceAddresses() public view returns (address[] memory) {
        return deviceAddresses;
    }

    // Get the IP address list of the devices in the group
    function getDeviceIps() public view returns (string[] memory) {
        return deviceIps;
    }

    // Get the address of the device by index
    function getDeviceAddressByIndex(
        uint256 _index
    ) public view returns (address) {
        return deviceAddresses[_index];
    }

    // Get the number of devices in the group
    function getDeviceLength() public view returns (uint256) {
        return deviceAddresses.length;
    }

    // Get the IP address of the specified device
    function getDeviceIp(address _address) public view returns (string memory) {
        return addressToDeviceInfo[_address].deviceIp;
    }

    // Get the public key of the specified device
    function getDevicePublicKey(
        address _address
    ) public view returns (bytes memory) {
        return addressToDeviceInfo[_address].deviceSecPublicKey;
    }

    // Get the expiration time of the specified device
    function getDeviceNotValidAfter(
        address _address
    ) public view returns (uint256) {
        return addressToDeviceInfo[_address].notValidAfter;
    }

    // Remove an element from the device address list
    // Remove members who have left the group
    function removeDeviceAddressAndIp(address _address) public {
        // deviceAddresses
        address[] memory m_deviceAddresses = deviceAddresses;
        string[] memory m_deviceIps = deviceIps;
        for (uint256 i = 0; i < m_deviceAddresses.length; i++) {
            if (m_deviceAddresses[i] == _address) {
                m_deviceAddresses[i] = m_deviceAddresses[
                    m_deviceAddresses.length - 1
                ];
                m_deviceIps[i] = m_deviceIps[m_deviceIps.length - 1];
                break;
            }
        }
        deviceAddresses = m_deviceAddresses;
        deviceAddresses.pop();
        deviceIps = m_deviceIps;
        deviceIps.pop();
    }

    // Process the leave request and trigger the GroupKeyUpdated event
    function deviceLeaveGroup(
        string memory _messageType,
        uint256 _timestamp,
        SignedMessage memory _messageSign,
        bytes32 _groupKeyHash,
        address[] memory _selfChainAddresses,
        bytes[] memory _encryptedGroupKeys
    ) public {
        require(
            keccak256(abi.encodePacked(_messageType)) ==
                keccak256(abi.encodePacked("leave group")),
            "MessageType is incorrect"
        );

        require(
            !groupKeyHashToBool[_groupKeyHash],
            "The groupKeyHash is exist"
        );

        require(
            block.timestamp < _timestamp ||
                block.timestamp - _timestamp < defaultTimeout,
            "Timestamp does not meet requirements"
        );

        // Verify that the hash of the request message is correct
        bytes32 sendMessageHash = keccak256(abi.encodePacked(_timestamp));
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        bytes32 requireMessageHash = keccak256(
            abi.encodePacked(prefix, sendMessageHash)
        );
        require(
            keccak256(abi.encodePacked(requireMessageHash)) ==
                keccak256(abi.encodePacked(_messageSign.msgh)),
            "There are incorrect sendMessageHash"
        );

        // Verify that the transaction sender is in the hash table
        address[] memory selfAddresses = publicKeyStorage.getSelfAddresses();
        uint256 requireNum = (selfAddresses.length - 1) / 3 + 1;
        uint256 startIndex = uint256(sendMessageHash) % selfAddresses.length;
        bool verifyMsgSender = false;
        for (uint256 i = 0; i < requireNum; i++) {
            if (
                msg.sender ==
                selfAddresses[(startIndex + i) % selfAddresses.length]
            ) {
                verifyMsgSender = true;
                break;
            }
        }
        require(verifyMsgSender, "The msg.sender is incorrect");

        // Verify that the device is still in the group
        // and that the signature of the request message is correct
        address signer = ecr(_messageSign);
        require(
            addressToDeviceInfo[signer].deviceStatus,
            "There are incorrect signer"
        );

        // Update device information
        addressToDeviceInfo[signer].deviceStatus = false;
        removeDeviceAddressAndIp(signer);

        // Store and update group key information
        for (uint256 i = 0; i < _selfChainAddresses.length; i++) {
            groupKeyHashToAddressToGroupKey[_groupKeyHash][
                _selfChainAddresses[i]
            ] = _encryptedGroupKeys[i];
        }
        groupKeyHashToGenerator[_groupKeyHash] = msg.sender;
        latestGroupKeyHashs[2] = latestGroupKeyHashs[1];
        latestGroupKeyHashs[1] = latestGroupKeyHashs[0];
        latestGroupKeyHashs[0] = _groupKeyHash;

        requireMessageHash = keccak256(
            abi.encodePacked(block.timestamp, _groupKeyHash)
        );
        recordMessageHashToBool[requireMessageHash] = true;

        // Contribution value of the key generator
        contributionStorage.addContributionForAddress(msg.sender, 0, 1);

        // Triggering the GroupKeyUpdated event
        emit GroupKeyUpdated(_groupKeyHash, block.timestamp);

        // Determine whether it is necessary to trigger an event\
        // to send a request message to the device
        // or directly update the reputation value
        if (
            uint256(sendMessageHash) % triggerThreshold < triggeringConditions
        ) {
            recordMessageHashToBool[sendMessageHash] = true;
            contributionStorage.updateReputationByGroupKey();
        }
    }

    // Handle certificate expiration events and trigger GroupKeyUpdated events
    function deviceCertInvalid(
        string memory _messageType,
        address[] memory _addresses,
        bytes32 _groupKeyHash,
        address[] memory _selfChainAddresses,
        bytes[] memory _encryptedGroupKeys
    ) public {
        require(
            keccak256(abi.encodePacked(_messageType)) ==
                keccak256(abi.encodePacked("cert invalid")),
            "MessageType is incorrect"
        );

        require(
            !groupKeyHashToBool[_groupKeyHash],
            "The groupKeyHash is exist"
        );

        // If the device is still in the group
        // and the certificate has expired, update the device information
        bool tag = false;
        for (uint256 i = 0; i < _addresses.length; i++) {
            if (
                addressToDeviceInfo[_addresses[i]].deviceStatus &&
                addressToDeviceInfo[_addresses[i]].notValidAfter <
                block.timestamp
            ) {
                addressToDeviceInfo[_addresses[i]].deviceStatus = false;
                removeDeviceAddressAndIp(_addresses[i]);
                tag = true;
            }
        }

        // If the device information has not change/d, the group key is not updated.
        require(tag, "No invalid cert found");

        for (uint256 i = 0; i < _selfChainAddresses.length; i++) {
            groupKeyHashToAddressToGroupKey[_groupKeyHash][
                _selfChainAddresses[i]
            ] = _encryptedGroupKeys[i];
        }
        groupKeyHashToGenerator[_groupKeyHash] = msg.sender;
        latestGroupKeyHashs[2] = latestGroupKeyHashs[1];
        latestGroupKeyHashs[1] = latestGroupKeyHashs[0];
        latestGroupKeyHashs[0] = _groupKeyHash;

        bytes32 recordMessageHash = keccak256(
            abi.encodePacked(block.timestamp, _groupKeyHash)
        );
        recordMessageHashToBool[recordMessageHash] = true;

        contributionStorage.addContributionForAddress(msg.sender, 0, 1);

        emit GroupKeyUpdated(_groupKeyHash, block.timestamp);

        if (
            uint256(recordMessageHash) % triggerThreshold < triggeringConditions
        ) {
            contributionStorage.updateReputationByGroupKey();
        }
    }

    // Handle changes in the blockchain address and trigger updates to the group key
    function selfAddressChanged(
        bytes32 _groupKeyHash,
        address[] memory _selfChainAddresses,
        bytes[] memory _encryptedGroupKeys
    ) public {
        // Verify whether the blockchain address has change/d
        require(
            publicKeyStorage.getChangedAddress() == msg.sender,
            "Message sender is incorrect"
        );

        for (uint256 i = 0; i < _selfChainAddresses.length; i++) {
            groupKeyHashToAddressToGroupKey[_groupKeyHash][
                _selfChainAddresses[i]
            ] = _encryptedGroupKeys[i];
        }
        groupKeyHashToGenerator[_groupKeyHash] = msg.sender;
        latestGroupKeyHashs[2] = latestGroupKeyHashs[1];
        latestGroupKeyHashs[1] = latestGroupKeyHashs[0];
        latestGroupKeyHashs[0] = _groupKeyHash;

        bytes32 recordMessageHash = keccak256(
            abi.encodePacked(block.timestamp, _groupKeyHash)
        );
        recordMessageHashToBool[recordMessageHash] = true;

        contributionStorage.addContributionForAddress(msg.sender, 0, 1);

        emit GroupKeyUpdated(_groupKeyHash, block.timestamp);

        if (
            uint256(
                keccak256(
                    abi.encodePacked(
                        _selfChainAddresses[_selfChainAddresses.length - 1]
                    )
                )
            ) %
                triggerThreshold <
            triggeringConditions
        ) {
            contributionStorage.updateReputationByGroupKey();
        }
    }

    // Initialize the clear operation
    function initDeviceAndGroupKey() public {
        uint256 length = deviceAddresses.length;
        for (uint256 i = 0; i < length; i++) {
            addressToDeviceInfo[deviceAddresses[i]].deviceStatus = false;
        }
        deviceAddresses = new address[](0);
        delete latestGroupKeyHashs[0];
        delete latestGroupKeyHashs[1];
        delete latestGroupKeyHashs[2];
    }

    // Determine whether a message exists
    function recordMessageHashIsExist(
        bytes32 _recordMessageHash
    ) public view returns (bool) {
        return recordMessageHashToBool[_recordMessageHash];
    }
}

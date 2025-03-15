// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.9.0;

// This contract is used to store the public keys of each blockchain node
contract PublicKeyStorage {
    // Create your own blockchain address list and public key mapping
    address[] public selfAddresses;
    mapping(address => bytes) public selfAddressToPublicKey;
    // Create a parent blockchain address list and public key mapping
    address[] public parentAddresses;
    mapping(address => bytes) public parentAddressToPublicKey;
    // Create a list of addresses and public key mappings for trusted certificate authorities
    address[] public caAddresses;

    uint256 public blockchianLevel;

    event SelfAddressesUpdated(uint256 changedTime, address changedAddress);
    address public changedAddress;

    constructor(uint256 _blockchianLevel) {
        blockchianLevel = _blockchianLevel;
    }

    function getBlockchianLevel() public view returns (uint256) {
        return blockchianLevel;
    }

    // ---------------------------------------------------------------------------
    // Check if the given address belongs to its own blockchain
    function checkSelfAddress(address _address) public view returns (bool) {
        for (uint256 i = 0; i < selfAddresses.length; i++) {
            if (_address == selfAddresses[i]) {
                return true;
            }
        }
        return false;
    }

    // Store the address of its own blockchain node
    function storeSelfAddresses(address[] memory _addresses) public {
        selfAddresses = _addresses;
    }

    // Adding new blockchain nodes
    function addSelfAddress(uint256 _changedTime, address _address) public {
        selfAddresses.push(_address);
        changedAddress = _address;
        emit SelfAddressesUpdated(_changedTime, _address);
    }

    // Remove a blockchain node
    function removeSelfAddress(uint256 _changedTime, address _address) public {
        address[] memory m_selfAddresses = selfAddresses;
        for (uint256 i = 0; i < m_selfAddresses.length; i++) {
            if (m_selfAddresses[i] == _address) {
                m_selfAddresses[i] = m_selfAddresses[
                    m_selfAddresses.length - 1
                ];
                break;
            }
        }
        selfAddresses = m_selfAddresses;
        selfAddresses.pop();
        changedAddress = _address;
        emit SelfAddressesUpdated(_changedTime, _address);
    }

    function getChangedAddress() public view returns (address) {
        return changedAddress;
    }

    // Get the number of nodes in its own blockchain
    // that is, the length of the address list
    function getSelfLength() public view returns (uint256) {
        return selfAddresses.length;
    }

    // Get the address list of its own blockchain
    function getSelfAddresses() public view returns (address[] memory) {
        return selfAddresses;
    }

    // Store the public key of your own blockchain node
    function storeSelfPublicKey(
        address _address,
        bytes memory _secPublicKey
    ) public {
        require(checkSelfAddress(_address), "Address does not exist!");
        selfAddressToPublicKey[_address] = _secPublicKey;
    }

    // Get the corresponding public key according to the address of its own blockchain
    function getSelfPublicKey(
        address _address
    ) public view returns (bytes memory) {
        require(checkSelfAddress(_address), "Address does not exist!");
        return selfAddressToPublicKey[_address];
    }

    //-----------------------------------------------------------------------------
    // Checks if the given address belongs to the parent blockchain
    function checkParentAddress(address _address) public view returns (bool) {
        for (uint256 i = 0; i < parentAddresses.length; i++) {
            if (_address == parentAddresses[i]) {
                return true;
            }
        }
        return false;
    }

    function storeParentAddresses(address[] memory _addresses) public {
        parentAddresses = _addresses;
    }

    function getParentLength() public view returns (uint256) {
        return parentAddresses.length;
    }

    function getParentAddresses() public view returns (address[] memory) {
        return parentAddresses;
    }

    function storeParentPublicKey(
        address _address,
        bytes memory _secPublicKey
    ) public {
        require(checkParentAddress(_address), "Address does not exist!");
        parentAddressToPublicKey[_address] = _secPublicKey;
    }

    function getParentPublicKey(
        address _address
    ) public view returns (bytes memory) {
        require(checkParentAddress(_address), "Address does not exist!");
        return parentAddressToPublicKey[_address];
    }

    //-----------------------------------------------------------------------------
    // Checks whether the given address belongs to a CA
    function checkCaAddress(address _address) public view returns (bool) {
        for (uint256 i = 0; i < caAddresses.length; i++) {
            if (_address == caAddresses[i]) {
                return true;
            }
        }
        return false;
    }

    function storeCaAddresses(address[] memory _addresses) public {
        caAddresses = _addresses;
    }

    function getCaLength() public view returns (uint256) {
        return caAddresses.length;
    }

    function getCaAddresses() public view returns (address[] memory) {
        return caAddresses;
    }
}

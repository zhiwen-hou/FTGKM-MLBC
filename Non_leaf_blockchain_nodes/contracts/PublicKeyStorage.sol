// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.9.0;

contract PublicKeyStorage {
    address[] public selfAddresses;
    mapping(address => bytes) public selfAddressToPublicKey;
    // Create a list of addresses and public key mappings for the child blockchain
    mapping(uint256 => address[]) public sonsAddresses;
    // Since there may be multiple sub-blockchains, mapping is used for storage
    mapping(uint256 => mapping(address => bytes)) public sonsAddressToPublicKey;

    uint256 public blockchianLevel;

    constructor(uint256 _blockchianLevel) {
        blockchianLevel = _blockchianLevel;
    }

    function getBlockchianLevel() public view returns (uint256) {
        return blockchianLevel;
    }

    // ---------------------------------------------------------------------------
    function checkSelfAddress(address _address) public view returns (bool) {
        for (uint256 i = 0; i < selfAddresses.length; i++) {
            if (_address == selfAddresses[i]) {
                return true;
            }
        }
        return false;
    }

    function storeSelfAddresses(address[] memory _addresses) public {
        selfAddresses = _addresses;
    }

    function getSelfLength() public view returns (uint256) {
        return selfAddresses.length;
    }

    function getSelfAddresses() public view returns (address[] memory) {
        return selfAddresses;
    }

    function storeSelfPublicKey(
        address _address,
        bytes memory _secPublicKey
    ) public {
        require(checkSelfAddress(_address), "Address does not exist!");
        selfAddressToPublicKey[_address] = _secPublicKey;
    }

    function getSelfPublicKey(
        address _address
    ) public view returns (bytes memory) {
        require(checkSelfAddress(_address), "Address does not exist!");
        return selfAddressToPublicKey[_address];
    }

    //------------------------------------------------------------------------------
    // Checks if the given address belongs to a child blockchain
    function checkSonAddress(
        uint256 _chainId,
        address _address
    ) public view returns (bool) {
        for (uint256 i = 0; i < sonsAddresses[_chainId].length; i++) {
            if (_address == sonsAddresses[_chainId][i]) {
                return true;
            }
        }
        return false;
    }

    function storeSonAddresses(
        uint256 _chainId,
        address[] memory _addresses
    ) public {
        sonsAddresses[_chainId] = _addresses;
    }

    function getSonLength(uint256 _chainId) public view returns (uint256) {
        return sonsAddresses[_chainId].length;
    }

    function getSonAddresses(
        uint256 _chainId
    ) public view returns (address[] memory) {
        return sonsAddresses[_chainId];
    }

    function storeSonPublicKey(
        uint256 _chainId,
        address _address,
        bytes memory _secPublicKey
    ) public {
        require(checkSonAddress(_chainId, _address), "Address does not exist!");
        sonsAddressToPublicKey[_chainId][_address] = _secPublicKey;
    }

    function getSonPublicKey(
        uint256 _chainId,
        address _address
    ) public view returns (bytes memory) {
        require(checkSonAddress(_chainId, _address), "Address does not exist!");
        return sonsAddressToPublicKey[_chainId][_address];
    }
}

// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.9.0;

import "./PublicKeyStorage.sol";

contract SimpleStorage {
    uint256 favoriteNumber;

    event StorageEvent(uint256 number);

    // This is a comment!
    struct People {
        uint256 favoriteNumber;
        string name;
    }

    struct Test9 {
        bool tag;
        uint256 num;
    }

    event addPersonEvent(People people);

    People[] public people;
    mapping(string => uint256) public nameToFavoriteNumber;
    mapping(string => string[]) public strToStrs;
    mapping(bytes32 => bytes) public bytes32Tobytes;
    mapping(bytes => bytes32) public bytesToBytes32;

    PublicKeyStorage public publicKeyStorage;
    address[] parentAddresses;

    mapping(address => Test9) public addressToTest9;

    event Event12(uint256 time, address[] addresses);

    event Event15(address testAddress);

    constructor(address _publicKeyStorageAddress) {
        publicKeyStorage = PublicKeyStorage(_publicKeyStorageAddress);
    }

    function store(uint256 _favoriteNumber) public {
        favoriteNumber = _favoriteNumber;
        emit StorageEvent(favoriteNumber);
    }

    function retrieve() public view returns (uint256) {
        return favoriteNumber;
    }

    function addPerson(string memory _name, uint256 _favoriteNumber) public {
        //People memory newPeople = People({favoriteNumber: _favoriteNumber, name: _name});
        //people.push(newPeople);
        people.push(People(_favoriteNumber, _name));
        nameToFavoriteNumber[_name] = _favoriteNumber;
        emit addPersonEvent(People(_favoriteNumber, _name));
    }

    function getPerson(
        string memory _name
    ) public view returns (People memory) {
        uint num = nameToFavoriteNumber[_name];
        return People(num, _name);
    }

    function getPersonNum(string memory _name) public view returns (uint256) {
        return nameToFavoriteNumber[_name];
    }

    // 测试1
    function addStr(string memory _str1, string memory _str2) public {
        strToStrs[_str1].push(_str2);
    }

    function getStr(string memory _str1) public view returns (string[] memory) {
        return strToStrs[_str1];
    }

    function getStrLength(string memory _str1) public view returns (uint256) {
        return strToStrs[_str1].length;
    }

    // 测试2
    function addBytes(bytes32 _bytes32, bytes memory _bytes) public {
        bytes32Tobytes[_bytes32] = _bytes;
    }

    function getBytes(bytes32 _bytes32) public view returns (bytes memory) {
        return bytes32Tobytes[_bytes32];
    }

    // 测试3
    function store2(uint256 _favoriteNumber) public {
        require(false, "test exception");
        //这种方式会弹出ValueError异常，并且不会生成新的块，即合约未调用成功
        favoriteNumber = _favoriteNumber;

        // 下面这种方式即便条件不满足，也只是未执行里面的代码而已
        // 合约还是调用了，还是会创建一个新的块
        // if(false){
        //     favoriteNumber = _favoriteNumber;
        // }
    }

    // 测试4
    function store3(uint256 _favoriteNumber) public {
        // uint256 selfLength = publicKeyStorage.getSelfLength();
        // require(_favoriteNumber > selfLength, "test4 exception");

        // address[] memory m_parentAddresses = publicKeyStorage.getParentAddresses();
        // require(_favoriteNumber > m_parentAddresses.length, "test4 exception");

        parentAddresses = publicKeyStorage.getParentAddresses();
        require(_favoriteNumber > parentAddresses.length, "test4 exception");

        // 上面三种情况，如果条件不满足，都会弹出ValueError异常，并且都不会生成新的块
        // 即自身合约未调用成功，publicKeyStorage的调用也未成功，所有不会产生新快

        favoriteNumber = _favoriteNumber;
    }

    //测试5
    function bytesToUint(bytes memory b) public pure returns (uint256) {
        uint256 number;
        for (uint i = 0; i < b.length; i++) {
            number = number + uint8(b[i]) * (2 ** (8 * (b.length - (i + 1))));
        }
        return number;
    }

    function getUintNumber(bytes32 _bytes32) public view returns (uint256) {
        return bytesToUint(bytes32Tobytes[_bytes32]);
    }

    function compareTo1500(
        bytes memory _bytesNumber
    ) public pure returns (bool) {
        uint256 number = bytesToUint(_bytesNumber);
        return number > 1500;
    }

    // 测试6
    // function uintToBytes(
    //     uint256 _uintNumber
    // ) public pure returns (bytes memory) {
    //     uint256 n1 = _uintNumber / 2;
    //     uint256 n2 = _uintNumber % 2;
    //     n1 = n1 + n2;
    //     bytes memory bytesNumber = abi.encodePacked(_uintNumber);
    //     bytes memory result = new bytes(n1);
    //     n2 = bytesNumber.length - n1;
    //     for (uint256 i = 0; i < n1; i++) {
    //         result[i] = bytesNumber[n2 + i];
    //     }
    //     return result;
    // }

    // function compareToSelf(
    //     bytes memory _bytesNumber
    // ) public pure returns (bool) {
    //     uint256 _uintNumber = bytesToUint(_bytesNumber);
    //     // bytes memory bytesNumber = abi.encodePacked(number);
    //     bytes memory convertBytesNumber = uintToBytes(_uintNumber);
    //     return keccak256(_bytesNumber) == keccak256(convertBytesNumber);
    // }

    function storeAccumulateHash(bytes32 _bytes32, bytes memory _bytes) public {
        bytesToBytes32[_bytes] = _bytes32;
    }

    function getAccumulateHashByIntNumber(
        bytes memory _bytesNumber
    ) public view returns (bytes32) {
        bytes memory bytesBlockNumber = abi.encodePacked(_bytesNumber);
        return bytesToBytes32[bytesBlockNumber];
    }

    // 测试7
    function verifyMergeHash(
        bytes memory _blockNumber,
        bytes32 _accumulateHash,
        bytes32 _mergeHash
    ) public pure returns (bool) {
        // bytes memory bytesBlockNumber = abi.encodePacked(_blockNumber);
        return
            keccak256(abi.encodePacked(_accumulateHash, _blockNumber)) ==
            _mergeHash;
    }

    // 测试8
    function store8(address[] memory _addresses) public {
        parentAddresses = _addresses;
    }

    function get8() public view returns (address[] memory) {
        return parentAddresses;
    }

    function set8(uint256 num, address _address) public {
        parentAddresses[num] = _address;
    }

    function remove8(uint256 num) public {
        delete parentAddresses[num];
    }

    function add8(address _address) public {
        parentAddresses.push(_address);
    }

    function renew8() public {
        address[] memory m_parentAddresses = parentAddresses;
        address[] memory tempArray = new address[](m_parentAddresses.length);
        uint256 count = 0;
        // 遍历原始数组，将非空地址存储到临时数组中
        for (uint256 i = 0; i < m_parentAddresses.length; i++) {
            if (m_parentAddresses[i] != address(0)) {
                tempArray[count] = m_parentAddresses[i];
                count++;
            }
        }

        // 创建一个新的动态数组，并将临时数组中的地址复制到新数组中
        address[] memory newArray = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            newArray[i] = tempArray[i];
        }
        // 使用新数组替换原始数组
        parentAddresses = newArray;
    }

    function delete8(address _address) public {
        address[] memory m_parentAddresses = parentAddresses;
        uint256 count = 0;
        for (uint256 i = 0; i < m_parentAddresses.length; i++) {
            if (m_parentAddresses[i] == _address) {
                count = i;
                break;
            }
        }
        parentAddresses[count] = parentAddresses[parentAddresses.length - 1];
        parentAddresses.pop();
    }

    function pop8() public {
        address[] memory m_parentAddresses = parentAddresses;
        uint256 count = 0;
        for (uint256 i = 0; i < m_parentAddresses.length; i++) {
            if (m_parentAddresses[i] == address(0)) {
                m_parentAddresses[i] = m_parentAddresses[
                    m_parentAddresses.length - 1 - count
                ];
                count++;
                if (i >= m_parentAddresses.length - 1 - count) {
                    break;
                }
            }
        }
        parentAddresses = m_parentAddresses;
        for (; count > 0; count--) {
            parentAddresses.pop();
        }
    }

    // 测试9
    function set9(address _address, bool _tag, uint256 _num) public {
        addressToTest9[_address] = Test9(_tag, _num);
    }

    function get9Bool(address _address) public view returns (bool) {
        return addressToTest9[_address].tag;
    }

    // 测试10
    function get10Hash(bytes memory _sign) public pure returns (bytes32) {
        bytes32 signHash = keccak256(abi.encodePacked(_sign));
        return signHash;
    }

    // 测试11
    function popAndGet11()
        public
        returns (uint256 time1, uint256 time2, uint256 time3)
    {
        uint256 time01 = block.timestamp;

        pop8();

        uint256 time02 = block.timestamp;

        uint256 time03 = time02 - time01;

        return (time01, time02, time03);
    }

    // 测试12
    function event12() public {
        emit Event12(block.timestamp, parentAddresses);
    }

    // 测试13
    function get12time() public view returns (uint256) {
        return block.timestamp;
    }

    // 测试14
    // 将bytes32类型的数据转成uint256类型的数据
    function bytes32ToUint256(bytes32 data) public pure returns (uint256) {
        return uint256(data);
    }

    function get14(bytes32 data) public pure returns (uint256) {
        uint256 num = uint256(data) % 7;
        return num;
    }

    // 测试15
    function event15(address _address) public {
        emit Event15(_address);
    }

    // 测试16
    function getHash(address[] memory _address) public pure returns (bytes32) {
        bytes memory abiencode = abi.encodePacked(_address[0]);
        for (uint256 i = 1; i < _address.length; i++) {
            abiencode = abi.encodePacked(abiencode, _address[i]);
        }

        return keccak256(abiencode);
    }

    // 测试17
    function getBytes32Hash18(
        uint256 _messageLevel,
        uint256 _timestamp,
        bytes32 _groupMessageHash
    ) public pure returns (bytes32) {
        // 计算消息哈希
        bytes32 sendMessageHash = keccak256(
            abi.encodePacked(_messageLevel, _timestamp, _groupMessageHash)
        );
        return sendMessageHash;
    }
}

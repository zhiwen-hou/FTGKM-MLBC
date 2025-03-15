// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.9.0;

contract SimpleStorage {
    uint256 favoriteNumber;

    event StorageEvent(uint256 number);

    // This is a comment!
    struct People {
        uint256 favoriteNumber;
        string name;
    }

    event addPersonEvent(People people);

    People[] public people;
    mapping(string => uint256) public nameToFavoriteNumber;
    mapping(string => string[]) public strToStrs;
    mapping(bytes32 => bytes) public bytes32Tobytes;

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
}

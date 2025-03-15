// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.9.0;

library VerifySignature {
    //数据验签入口函数
    function verifyByHashAndSig(
        bytes32 messageHash,
        bytes memory signature
    ) internal pure returns (address) {
        bytes memory signedString = signature;

        bytes32 r = bytesToBytes32(slice(signedString, 0, 32));
        bytes32 s = bytesToBytes32(slice(signedString, 32, 32));
        bytes1 v1 = slice(signedString, 64, 1)[0];
        uint8 v = uint8(v1) + 27;
        return ecrecoverDirect(messageHash, r, s, v);
    }

    //将原始数据按段切割出来指定长度
    function slice(
        bytes memory data,
        uint start,
        uint len
    ) internal pure returns (bytes memory) {
        bytes memory b = new bytes(len);

        for (uint i = 0; i < len; i++) {
            b[i] = data[i + start];
        }
        return b;
    }

    //bytes转换为bytes32
    function bytesToBytes32(
        bytes memory source
    ) internal pure returns (bytes32 result) {
        assembly {
            result := mload(add(source, 32))
        }
    }

    //使用ecrecover恢复公匙
    function ecrecoverDirect(
        bytes32 messageHash,
        bytes32 r,
        bytes32 s,
        uint8 v
    ) internal pure returns (address addr) {
        /* prefix might be needed for geth only
         * https://github.com/ethereum/go-ethereum/issues/3731
         */
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        messageHash = keccak256(abi.encodePacked(prefix, messageHash));

        addr = ecrecover(messageHash, v, r, s);
    }
}

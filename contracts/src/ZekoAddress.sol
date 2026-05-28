// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

type ZekoAddress is uint256;

library ZekoAddressLib {
    uint256 internal constant SIGN_MASK = 1 << 255;
    uint256 internal constant X_MASK = SIGN_MASK - 1;

    // Zeko/Pasta base field order.
    uint256 internal constant ZEKO_FIELD_ORDER =
        28948022309329048855892746252171976963363056481941560715954676764349967630337;

    error InvalidZekoField();

    function pack(uint256 x, bool isOdd) internal pure returns (ZekoAddress) {
        if (x >= ZEKO_FIELD_ORDER) revert InvalidZekoField();

        uint256 packed = x | (isOdd ? SIGN_MASK : 0);
        return ZekoAddress.wrap(packed);
    }

    function unpack(
        ZekoAddress zeko
    ) internal pure returns (uint256 x, bool isOdd) {
        uint256 packed = ZekoAddress.unwrap(zeko);

        x = packed & X_MASK;
        isOdd = (packed & SIGN_MASK) != 0;

        if (x >= ZEKO_FIELD_ORDER) revert InvalidZekoField();
    }

    function raw(ZekoAddress zeko) internal pure returns (uint256) {
        return ZekoAddress.unwrap(zeko);
    }

    function fromRaw(uint256 packed) internal pure returns (ZekoAddress) {
        uint256 x = packed & X_MASK;

        if (x >= ZEKO_FIELD_ORDER) revert InvalidZekoField();

        return ZekoAddress.wrap(packed);
    }
}

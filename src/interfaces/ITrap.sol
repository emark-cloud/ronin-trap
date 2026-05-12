// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ITrap {
    function collect() external view returns (bytes memory);
    function shouldRespond(bytes[] calldata data) external pure returns (bool, bytes memory);
}

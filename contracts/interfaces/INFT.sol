// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";

interface INFT is IERC1155 {
    function createNFT(
        address royaltyReceiver,
        uint96 royaltyBasisPoints,
        string calldata tokenURI
    ) external;

    function totalTokenIds() external view returns (uint256);
}

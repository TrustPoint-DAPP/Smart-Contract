// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract Logger {
    mapping(address => bool) public nftContracts;

    address public owner;

    event TransferSingle(
        address indexed contractAddress,
        address operator,
        address from,
        address to,
        uint256 id,
        uint256 value
    );
    event TransferBatch(
        address indexed contractAddress,
        address operator,
        address from,
        address to,
        uint256[] ids,
        uint256[] values
    );
    event ApprovalForAll(
        address indexed contractAddress,
        address indexed account,
        address indexed operator,
        bool approved
    );
    event URI(
        address indexed contractAddress,
        string value,
        uint256 indexed id
    );

    error OnlyNFTContractsAllowed();
    error Unauthorized();

    constructor() {
        owner = msg.sender;
    }

    modifier onlyNFTContract() {
        if (!nftContracts[msg.sender]) revert OnlyNFTContractsAllowed();
        _;
    }

    function addNFTContract(address contractAddress) public {
        if (owner != msg.sender) revert Unauthorized();
        nftContracts[contractAddress] = true;
    }

    function emitTransferSingle(
        address operator,
        address from,
        address to,
        uint256 id,
        uint256 value
    ) public onlyNFTContract {
        emit TransferSingle(msg.sender, operator, from, to, id, value);
    }

    function emitTransferBatch(
        address operator,
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata values
    ) public onlyNFTContract {
        emit TransferBatch(msg.sender, operator, from, to, ids, values);
    }

    function emitApprovalForAll(
        address account,
        address operator,
        bool approved
    ) public onlyNFTContract {
        emit ApprovalForAll(msg.sender, account, operator, approved);
    }

    function emitURI(string calldata value, uint256 id) public onlyNFTContract {
        emit URI(msg.sender, value, id);
    }
}

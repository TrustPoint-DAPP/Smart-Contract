// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/token/common/ERC2981.sol";
import "./extensions/CustomERC1155Burnable.sol";
import "./extensions/CustomERC1155Supply.sol";
import "./extensions/CustomERC1155URIStorage.sol";
import "./interfaces/IOrganizationController.sol";
import "./interfaces/INFT.sol";
import "./CustomERC1155.sol";
import "./Logger.sol";

contract NFT is
    CustomERC1155,
    Ownable,
    Pausable,
    CustomERC1155Burnable,
    CustomERC1155Supply,
    CustomERC1155URIStorage,
    ERC2981,
    INFT
{
    IOrganizationController public organizationController;
    uint256 public orgId;
    address public dealMaker;
    uint256 public totalTokenIds;

    error Unauthorized();
    error NFTNotFound();

    event PermanentURI(string _value, uint256 indexed _id);

    constructor(
        uint256 _orgId,
        address _dealMaker,
        Logger _logger
    ) CustomERC1155("", _logger) {
        _setBaseURI("ipfs://");
        organizationController = IOrganizationController(msg.sender);
        orgId = _orgId;
        dealMaker = _dealMaker;
        emit OwnershipTransferred(
            address(0),
            organizationController.getOrganization(_orgId).admin
        );
    }

    modifier onlyDealMaker() {
        if (msg.sender != dealMaker) revert Unauthorized();
        _;
    }

    function createNFT(
        address royaltyReceiver,
        uint96 royaltyBasisPoints,
        string calldata tokenURI
    ) public onlyDealMaker {
        uint256 tokenId = totalTokenIds++;
        _setURI(tokenId, tokenURI);
        _setTokenRoyalty(tokenId, royaltyReceiver, royaltyBasisPoints);
        emit PermanentURI(tokenURI, tokenId);
    }

    function pause() public onlyOwner {
        _pause();
    }

    function unpause() public onlyOwner {
        _unpause();
    }

    function mint(
        address account,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) public onlyOwner {
        if (id >= totalTokenIds) revert NFTNotFound();
        _mint(account, id, amount, data);
    }

    function mintBatch(
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) public onlyOwner {
        for (uint256 i = 0; i < ids.length; i++) {
            if (ids[i] >= totalTokenIds) revert NFTNotFound();
        }
        _mintBatch(to, ids, amounts, data);
    }

    function uri(uint256 tokenId)
        public
        view
        virtual
        override(CustomERC1155, CustomERC1155URIStorage)
        returns (string memory)
    {
        if (tokenId >= totalTokenIds) revert NFTNotFound();
        return super.uri(tokenId);
    }

    // overriding Ownable functions to use Organization Controller

    function owner() public view virtual override returns (address) {
        if (organizationController.getOrganization(orgId).isLocked)
            return address(0);
        return organizationController.getOrganization(orgId).admin;
    }

    function renounceOwnership() public virtual override onlyOwner {
        address oldOwner = owner();
        organizationController.lockOrganization(orgId);
        emit OwnershipTransferred(oldOwner, address(0));
    }

    function _transferOwnership(address newOwner) internal virtual override {
        address oldOwner = owner();
        organizationController.updateAdmin(orgId, newOwner);
        emit OwnershipTransferred(oldOwner, newOwner);
    }

    function _beforeTokenTransfer(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal override(CustomERC1155, CustomERC1155Supply) whenNotPaused {
        super._beforeTokenTransfer(operator, from, to, ids, amounts, data);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(IERC165, CustomERC1155, ERC2981)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}

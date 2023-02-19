// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "./interfaces/IOrganizationController.sol";
import "./NFT.sol";

/// @custom:security-contact contact@yashgoyal.dev
contract OrganizationController is
    Pausable,
    AccessControl,
    EIP712,
    IOrganizationController
{
    using ECDSA for bytes32;
    Logger public immutable logger;

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant DEAL_MAKER_ROLE = keccak256("DEAL_MAKER_ROLE");

    mapping(uint256 => Organization) public organizations;
    mapping(address => uint256) public orgIdOf;

    constructor() EIP712("OrganizationController", "1") {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
        _grantRole(DEAL_MAKER_ROLE, msg.sender);
        logger = new Logger();
    }

    modifier onlyNFTContract(uint256 id) {
        if (!exists(id)) revert InvalidOrganizationId();
        if (organizations[id].nftContract != msg.sender)
            revert OnlyNFTContractAllowed();
        _;
    }

    function createOrganization(uint256 orgId, address admin)
        public
        onlyRole(DEAL_MAKER_ROLE)
    {
        if (exists(orgId)) revert OrganizationAlreadyExists();
        if (orgIdOf[admin] != 0) revert OneAdminCanHaveOnlyOneOrganization();

        orgIdOf[admin] = orgId;
        organizations[orgId] = Organization({
            id: orgId,
            admin: admin,
            nftContract: address(0),
            isLocked: false
        });

        // deploy a nft contract for the organization
        address nftContract = address(new NFT(orgId, msg.sender, logger));
        logger.addNFTContract(nftContract);
        organizations[orgId].nftContract = nftContract;

        emit CreateOrganization(orgId, admin, nftContract);
    }

    function getOrganization(uint256 id)
        public
        view
        returns (Organization memory)
    {
        if (!exists(id)) revert InvalidOrganizationId();
        return organizations[id];
    }

    function totalNFTs(uint256 id) external view returns (uint256) {
        Organization memory organization = getOrganization(id);
        NFT nft = NFT(organization.nftContract);
        return nft.totalTokenIds();
    }

    function updateAdmin(uint256 id, address newAdmin)
        external
        onlyNFTContract(id)
    {
        if (orgIdOf[newAdmin] != 0) revert OneAdminCanHaveOnlyOneOrganization();
        address oldAdmin = organizations[id].admin;
        organizations[id].admin = newAdmin;
        orgIdOf[newAdmin] = id;
        orgIdOf[oldAdmin] = 0;
        emit AdminUpdated(id, oldAdmin, newAdmin);
    }

    function lockOrganization(uint256 id) external onlyNFTContract(id) {
        organizations[id].isLocked = true;
        emit OrganizationLocked(id);
    }

    function exists(uint256 id) public view returns (bool) {
        return organizations[id].admin != address(0);
    }

    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
    }
}

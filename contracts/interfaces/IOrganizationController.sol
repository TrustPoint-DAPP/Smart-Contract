// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

interface IOrganizationController {
    struct Organization {
        uint256 id;
        address admin;
        address nftContract;
        bool isLocked;
    }

    error OneAdminCanHaveOnlyOneOrganization();
    error OrganizationAlreadyExists();
    error InvalidOrganizationId();
    error OnlyNFTContractAllowed();

    event CreateOrganization(
        uint256 indexed orgId,
        address indexed adminAddress
    );
    event AdminUpdated(
        uint256 indexed orgId,
        address indexed oldAdmin,
        address indexed newAdmin
    );
    event OrganizationLocked(uint256 indexed orgId);

    function createOrganization(uint256 orgId, address admin) external;

    function getOrganization(uint256 id)
        external
        view
        returns (Organization memory);

    function totalNFTs(uint256 id) external view returns (uint256);

    function updateAdmin(uint256 id, address newAdmin) external;

    function lockOrganization(uint256 id) external;

    function exists(uint256 id) external view returns (bool);
}

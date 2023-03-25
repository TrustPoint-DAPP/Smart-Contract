// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/finance/PaymentSplitter.sol";
import "./interfaces/IOrganizationController.sol";
import "./interfaces/INFT.sol";

/// @custom:security-contact contact@yashgoyal.dev
contract DealController is Pausable, AccessControl, EIP712 {
    using ECDSA for bytes32;

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");

    uint96 public feeRoyaltyBasisPoints;
    uint256 public oneOffFeeBasisPoints;
    address public feeCollector;

    struct Deal {
        uint256 id;
        uint256 orgId;
        uint256 oneOffPayment;
        uint256 noOfNFTs;
        address counterParty;
        address orgRoyaltyReceiver;
        bool done;
        bool cancelled;
    }

    struct NFT {
        uint256 id;
        uint256 dealId;
        string nftCID;
        uint96 royaltyBasisPoints;
        uint96 orgRoyaltyBasisPoints;
        address royaltySplitter;
        uint256 tokenId;
        bool created;
    }

    uint256 public totalDeals;
    uint256 public totalNFTs;

    mapping(address => uint256) public orgIdOf;
    mapping(uint256 => NFT) public nfts;
    mapping(uint256 => Deal) public deals;
    mapping(uint256 => uint256[]) public nftsInDeal;
    mapping(uint256 => bool) isNonceUsed;

    IOrganizationController public organizationController;

    event DealCreated(Deal deal, NFT[] nfts);

    event DealCancelled(
        uint256 indexed dealId,
        uint256 indexed organizationId,
        address indexed counterParty
    );
    event DealCompleted(
        uint256 indexed dealId,
        uint256 indexed organizationId,
        address indexed counterParty,
        uint256[] nftIds,
        uint256[] tokenIds,
        address[] royaltyReceivers
    );

    error InvalidNonce();
    error InvalidValue();
    error InvalidDealId();
    error InvalidSignature();
    error OneAdminCanHaveOnlyOneOrganization();
    error Unauthorized();
    error DealAlreadyDone();
    error DealAlreadyCancelled();
    error EthTransferFailed();
    error InvalidBasisPoints();
    error CannotSetToZeroAddress();

    constructor(
        IOrganizationController _organizationController,
        address _feeCollector,
        uint256 _oneOffFeeBasisPoints,
        uint96 _feeRoyaltyBasisPoints
    ) EIP712("Deal Controller", "1") {
        if (_feeCollector == address(0)) revert CannotSetToZeroAddress();
        if (_oneOffFeeBasisPoints > 10000) revert InvalidBasisPoints();
        if (_feeRoyaltyBasisPoints > 10000) revert InvalidBasisPoints();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
        _grantRole(SIGNER_ROLE, msg.sender);

        organizationController = _organizationController;
        feeCollector = _feeCollector;
        oneOffFeeBasisPoints = _oneOffFeeBasisPoints;
        feeRoyaltyBasisPoints = _feeRoyaltyBasisPoints;
    }

    function createDeal(
        uint256 orgId,
        uint256 amount,
        uint96 royaltyBasisPoints,
        uint96 orgRoyaltyBasisPoints,
        address counterParty,
        address orgRoyaltyReceiver,
        string calldata nftCID,
        uint256 nonce,
        bytes calldata signature
    ) public payable {
        if (isNonceUsed[nonce]) revert InvalidNonce();
        if (
            orgRoyaltyBasisPoints + royaltyBasisPoints + feeRoyaltyBasisPoints >
            10000
        ) revert InvalidBasisPoints();
        if (msg.value != amount) revert InvalidValue();

        // verify signature
        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    keccak256(
                        "CreateDeal(uint256 orgId,address orgAdmin,uint256 amount,uint96 royaltyBasisPoints,uint96 orgRoyaltyBasisPoints,address counterParty,address orgRoyaltyReceiver,string nftCID,uint256 nonce)"
                    ),
                    orgId,
                    msg.sender,
                    amount,
                    royaltyBasisPoints,
                    orgRoyaltyBasisPoints,
                    counterParty,
                    orgRoyaltyReceiver,
                    keccak256(abi.encodePacked((nftCID))),
                    nonce
                )
            )
        );
        address _signer = digest.recover(signature);
        if (!hasRole(SIGNER_ROLE, _signer)) revert InvalidSignature();
        isNonceUsed[nonce] = true;

        // create organization if not exists already
        if (organizationController.exists(orgId)) {
            if (
                organizationController.getOrganization(orgId).admin !=
                msg.sender
            ) revert Unauthorized();
        } else {
            organizationController.createOrganization(orgId, msg.sender);
        }

        // create the deal struct
        uint256 dealId = ++totalDeals;
        deals[dealId] = Deal({
            id: dealId,
            orgId: orgId,
            noOfNFTs: 1,
            counterParty: counterParty,
            orgRoyaltyReceiver: orgRoyaltyReceiver,
            oneOffPayment: amount,
            done: false,
            cancelled: false
        });

        // create the nft struct
        uint256 nftId = ++totalNFTs;
        nfts[nftId] = NFT({
            id: nftId,
            dealId: dealId,
            nftCID: nftCID,
            royaltyBasisPoints: royaltyBasisPoints,
            orgRoyaltyBasisPoints: orgRoyaltyBasisPoints,
            royaltySplitter: address(0),
            tokenId: 0,
            created: false
        });

        // add the nft in deal
        nftsInDeal[dealId].push(nftId);

        // emit the event
        NFT[] memory nftObjs = new NFT[](1);
        nftObjs[0] = nfts[nftId];
        emit DealCreated(deals[dealId], nftObjs);
    }

    function acceptDeal(uint256 dealId, address royaltyReceiver) public {
        if (!dealExists(dealId)) revert InvalidDealId();
        if (royaltyReceiver == address(0)) revert CannotSetToZeroAddress();
        Deal memory deal = deals[dealId];
        if (deal.counterParty != msg.sender) revert Unauthorized();
        if (deal.done) revert DealAlreadyDone();
        if (deal.cancelled) revert DealAlreadyCancelled();

        // mark the deal done
        deals[dealId].done = true;

        // fetch the organization nft collection
        INFT nftContract = INFT(
            organizationController.getOrganization(deal.orgId).nftContract
        );

        // create the royalty payees array
        address[] memory payees = new address[](3);
        payees[0] = feeCollector;
        payees[1] = deal.orgRoyaltyReceiver;
        payees[2] = royaltyReceiver;

        uint256[] memory tokenIds = new uint256[](deal.noOfNFTs);
        address[] memory royaltyReceivers = new address[](deal.noOfNFTs);

        // create the nfts
        for (uint256 i = 0; i < deal.noOfNFTs; i++) {
            // fetch the nft struct
            uint256 nftId = nftsInDeal[dealId][i];
            NFT memory nft = nfts[nftId];

            // create the royalty shares array
            uint256[] memory shares = new uint256[](3);
            shares[0] = uint256(feeRoyaltyBasisPoints);
            shares[1] = uint256(nft.orgRoyaltyBasisPoints);
            shares[2] = uint256(nft.royaltyBasisPoints);

            // deploy the royalty splitter
            address royaltySplitter = address(
                new PaymentSplitter(payees, shares)
            );

            // total royalty
            uint96 totalRoyaltyBasisPoints = feeRoyaltyBasisPoints +
                nft.orgRoyaltyBasisPoints +
                nft.royaltyBasisPoints;

            // update the arrays for event
            tokenIds[i] = nftContract.totalTokenIds();
            royaltyReceivers[i] = royaltyReceiver;

            // update the info on the nft struct
            nfts[nftId].royaltySplitter = royaltySplitter;
            nfts[nftId].tokenId = tokenIds[i];
            nfts[nftId].created = true;

            // create the nft on the nft contract
            nftContract.createNFT(
                royaltySplitter,
                totalRoyaltyBasisPoints,
                nft.nftCID
            );
        }

        // transfer the fees and payment
        uint256 fees = (deal.oneOffPayment * oneOffFeeBasisPoints) / 10000;
        _transferEther(feeCollector, fees);
        _transferEther(msg.sender, deal.oneOffPayment - fees);

        emit DealCompleted(
            dealId,
            deal.orgId,
            deal.counterParty,
            nftsInDeal[dealId],
            tokenIds,
            royaltyReceivers
        );
    }

    function cancelDeal(uint256 dealId) public {
        if (!dealExists(dealId)) revert InvalidDealId();
        Deal memory deal = deals[dealId];
        if (
            organizationController.getOrganization(deal.orgId).admin !=
            msg.sender
        ) revert Unauthorized();
        if (deal.done) revert DealAlreadyDone();
        if (deal.cancelled) revert DealAlreadyCancelled();

        // mark the deal cancelled
        deals[dealId].cancelled = true;

        // transfer the amount back to the org admin
        _transferEther(msg.sender, deal.oneOffPayment);

        emit DealCancelled(dealId, deal.orgId, deal.counterParty);
    }

    function dealExists(uint256 dealId) public view returns (bool) {
        return dealId != 0 && dealId <= totalDeals;
    }

    // admin functions

    function setFeeRoyaltyBasisPoints(uint96 _feeRoyaltyBasisPoints)
        public
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (_feeRoyaltyBasisPoints > 10000) revert InvalidBasisPoints();
        feeRoyaltyBasisPoints = _feeRoyaltyBasisPoints;
    }

    function setOneOffFeeBasisPoints(uint256 _oneOffFeeBasisPoints)
        public
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (_oneOffFeeBasisPoints > 10000) revert InvalidBasisPoints();
        oneOffFeeBasisPoints = _oneOffFeeBasisPoints;
    }

    function setFeeCollector(address _feeCollector)
        public
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (_feeCollector == address(0)) revert CannotSetToZeroAddress();
        feeCollector = _feeCollector;
    }

    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    // private helper functions

    function _transferEther(address receiver, uint256 amount) private {
        (bool success, ) = receiver.call{value: amount}("");
        if (!success) revert EthTransferFailed();
    }
}

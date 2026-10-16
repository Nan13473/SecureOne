// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract VeriBindCredential is ERC721, Ownable {
    enum Status { Pending, Confirmed, Disputed }
    enum Role { None, Holder, Issuer, Verifier }

    struct Credential {
        bytes32 identityHash;
        bytes32 merkleRoot;
        bytes32 photoHash;
        string cid;
        bytes32 ciphertextHash;
        bytes32 issuanceDigest;
        uint8 schemaVersion;
        uint64 issuedAt;
        uint64 expiresAt;
        Status status;
    }

    struct Issuance {
        address holder;
        bytes32 merkleRoot;
        bytes32 photoHash;
        string cid;
        bytes32 ciphertextHash;
        bytes32 issuanceDigest;
        uint8 schemaVersion;
        uint64 expiresAt;
        uint8 approvals;
        bool finalized;
    }

    uint256 private _nextTokenId = 1;
    mapping(address => bytes32) public registeredIdentity;
    mapping(bytes32 => address) public identityHashOwner;
    address[] private _registeredHolders;
    mapping(uint256 => Credential) public credentials;
    mapping(address => uint256[]) private _holderTokenIds;
    mapping(address => bool) public authorizedIssuer;
    mapping(address => bytes32) public issuerAccreditationHash;
    mapping(uint256 => Issuance) public issuances;
    mapping(uint256 => mapping(address => bool)) public hasApproved;
    uint256 private _nextIssuanceId = 1;
    uint8 public immutable APPROVAL_THRESHOLD;

    event IdentityRegistered(address indexed holder, bytes32 indexed docHash);
    event CredentialMinted(uint256 indexed tokenId, address indexed holder, bytes32 merkleRoot, string cid, bytes32 issuanceDigest);
    event StatusChanged(uint256 indexed tokenId, Status status);
    event IssuerUpdated(address indexed issuer, bool authorized);
    event IssuerVerificationRequested(address indexed issuer, bytes32 indexed accreditationHash);
    event IssuanceProposed(uint256 indexed issuanceId, address indexed holder, bytes32 merkleRoot, string cid);
    event IssuanceApproved(uint256 indexed issuanceId, address indexed issuer);

    error IdentityNotRegistered();
    error OnlyHolder();
    error InvalidStatus();
    error Soulbound();
    error NotIssuer();
    error AlreadyApproved();
    error AlreadyFinalized();
    error ApprovalThresholdNotMet();
    error AccreditationNotSubmitted();
    error IdentityHashAlreadyRegistered();
    error InvalidIdentityHash();
    error InvalidApprovalThreshold();

    constructor(uint8 approvalThreshold_) ERC721("VeriBind Credential", "VBC") Ownable(msg.sender) {
        if (approvalThreshold_ == 0) revert InvalidApprovalThreshold();
        APPROVAL_THRESHOLD = approvalThreshold_;
        authorizedIssuer[msg.sender] = true;
        emit IssuerUpdated(msg.sender, true);
    }

    modifier onlyIssuer() {
        if (!authorizedIssuer[msg.sender]) revert NotIssuer();
        _;
    }

    function setIssuer(address issuer, bool authorized) external onlyOwner {
        if (authorized && issuerAccreditationHash[issuer] == bytes32(0)) revert AccreditationNotSubmitted();
        authorizedIssuer[issuer] = authorized;
        emit IssuerUpdated(issuer, authorized);
    }

    function requestIssuerVerification(bytes32 accreditationHash) external {
        if (accreditationHash == bytes32(0)) revert AccreditationNotSubmitted();
        issuerAccreditationHash[msg.sender] = accreditationHash;
        emit IssuerVerificationRequested(msg.sender, accreditationHash);
    }

    function roleOf(address account) external view returns (Role) {
        if (authorizedIssuer[account]) return Role.Issuer;
        if (registeredIdentity[account] != bytes32(0)) return Role.Holder;
        return Role.Verifier;
    }

    function registerIdentity(bytes32 docHash) external {
        if (docHash == bytes32(0)) revert InvalidIdentityHash();
        address existingOwner = identityHashOwner[docHash];
        if (existingOwner != address(0) && existingOwner != msg.sender) revert IdentityHashAlreadyRegistered();
        if (registeredIdentity[msg.sender] == bytes32(0)) _registeredHolders.push(msg.sender);
        registeredIdentity[msg.sender] = docHash;
        identityHashOwner[docHash] = msg.sender;
        emit IdentityRegistered(msg.sender, docHash);
    }

    function registeredHolderCount() external view returns (uint256) { return _registeredHolders.length; }
    function registeredHolderAt(uint256 index) external view returns (address) { return _registeredHolders[index]; }
    function holderCredentialCount(address holder) external view returns (uint256) { return _holderTokenIds[holder].length; }
    function holderCredentialAt(address holder, uint256 index) external view returns (uint256) { return _holderTokenIds[holder][index]; }

    function proposeIssuance(
        address holder,
        bytes32 merkleRoot,
        bytes32 photoHash,
        string calldata cid,
        bytes32 ciphertextHash,
        bytes32 issuanceDigest,
        uint8 schemaVersion,
        uint64 expiresAt
    ) external onlyIssuer returns (uint256 issuanceId) {
        if (registeredIdentity[holder] == bytes32(0)) revert IdentityNotRegistered();
        issuanceId = _nextIssuanceId++;
        issuances[issuanceId] = Issuance(holder, merkleRoot, photoHash, cid, ciphertextHash, issuanceDigest, schemaVersion, expiresAt, 0, false);
        emit IssuanceProposed(issuanceId, holder, merkleRoot, cid);
    }

    function approveIssuance(uint256 issuanceId) external onlyIssuer {
        Issuance storage issuance = issuances[issuanceId];
        if (issuance.finalized) revert AlreadyFinalized();
        if (hasApproved[issuanceId][msg.sender]) revert AlreadyApproved();
        hasApproved[issuanceId][msg.sender] = true;
        issuance.approvals += 1;
        emit IssuanceApproved(issuanceId, msg.sender);
    }

    function finalizeIssuance(uint256 issuanceId) external onlyIssuer returns (uint256 tokenId) {
        Issuance storage issuance = issuances[issuanceId];
        if (issuance.finalized) revert AlreadyFinalized();
        if (issuance.approvals < APPROVAL_THRESHOLD) revert ApprovalThresholdNotMet();
        issuance.finalized = true;
        tokenId = _mintCredential(issuance.holder, issuance.merkleRoot, issuance.photoHash, issuance.cid, issuance.ciphertextHash, issuance.issuanceDigest, issuance.schemaVersion, issuance.expiresAt);
    }

    function _mintCredential(
        address holder,
        bytes32 merkleRoot,
        bytes32 photoHash,
        string memory cid,
        bytes32 ciphertextHash,
        bytes32 issuanceDigest,
        uint8 schemaVersion,
        uint64 expiresAt
    ) internal returns (uint256 tokenId) {
        bytes32 identityHash = registeredIdentity[holder];
        if (identityHash == bytes32(0)) revert IdentityNotRegistered();
        tokenId = _nextTokenId++;
        _safeMint(holder, tokenId);
        _holderTokenIds[holder].push(tokenId);
        credentials[tokenId] = Credential(identityHash, merkleRoot, photoHash, cid, ciphertextHash, issuanceDigest, schemaVersion, uint64(block.timestamp), expiresAt, Status.Pending);
        emit CredentialMinted(tokenId, holder, merkleRoot, cid, issuanceDigest);
    }

    function credentialRecipient(uint256 tokenId) external view returns (address) { return ownerOf(tokenId); }
    function credentialStatus(uint256 tokenId) external view returns (Status) { return credentials[tokenId].status; }
    function credentialMerkleRoot(uint256 tokenId) external view returns (bytes32) { return credentials[tokenId].merkleRoot; }
    function credentialPhotoHash(uint256 tokenId) external view returns (bytes32) { return credentials[tokenId].photoHash; }
    function credentialCid(uint256 tokenId) external view returns (string memory) { return credentials[tokenId].cid; }
    function credentialCiphertextHash(uint256 tokenId) external view returns (bytes32) { return credentials[tokenId].ciphertextHash; }
    function credentialIssuanceDigest(uint256 tokenId) external view returns (bytes32) { return credentials[tokenId].issuanceDigest; }
    function credentialIssuedAt(uint256 tokenId) external view returns (uint64) { return credentials[tokenId].issuedAt; }
    function credentialExpiresAt(uint256 tokenId) external view returns (uint64) { return credentials[tokenId].expiresAt; }

    function confirm(uint256 tokenId) external {
        if (ownerOf(tokenId) != msg.sender) revert OnlyHolder();
        if (credentials[tokenId].status != Status.Pending) revert InvalidStatus();
        credentials[tokenId].status = Status.Confirmed;
        emit StatusChanged(tokenId, Status.Confirmed);
    }

    function dispute(uint256 tokenId) external {
        if (ownerOf(tokenId) != msg.sender) revert OnlyHolder();
        if (credentials[tokenId].status != Status.Pending) revert InvalidStatus();
        credentials[tokenId].status = Status.Disputed;
        emit StatusChanged(tokenId, Status.Disputed);
    }

    function _update(address to, uint256 tokenId, address auth) internal override returns (address) {
        address from = _ownerOf(tokenId);
        if (from != address(0) && to != address(0)) revert Soulbound();
        return super._update(to, tokenId, auth);
    }
}

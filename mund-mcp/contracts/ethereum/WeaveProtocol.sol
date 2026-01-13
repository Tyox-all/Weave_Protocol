// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title WeaveProtocol
 * @notice Thread anchoring for AI agent verification
 * @dev Part of the Weave Security Suite (Mund + Hord + Dōmere)
 */
contract WeaveProtocol {
    // ========================================================================
    // State
    // ========================================================================
    
    struct ThreadAnchor {
        bytes32 merkleRoot;
        uint64 hopCount;
        bytes32 intentHash;
        bool compliant;
        uint256 timestamp;
        address anchorer;
    }
    
    struct BatchAnchor {
        bytes32 merkleRoot;
        uint64 threadCount;
        uint256 timestamp;
        address anchorer;
    }
    
    struct Violation {
        bytes32 threadId;
        uint8 violationType;
        uint8 severity;
        bytes32 descriptionHash;
        uint256 timestamp;
        address reporter;
        bool resolved;
        bytes32 resolutionHash;
        uint256 resolvedAt;
        address resolver;
    }
    
    // Thread ID => Anchor
    mapping(bytes32 => ThreadAnchor) public threadAnchors;
    
    // Batch ID => Anchor
    mapping(bytes32 => BatchAnchor) public batchAnchors;
    
    // Violation ID => Violation
    mapping(bytes32 => Violation) public violations;
    
    // Thread ID => Violation count
    mapping(bytes32 => uint256) public violationCounts;
    
    // Protocol fee (5% of gas, implemented via suggested donation)
    uint256 public protocolFeeBps = 500;
    
    // Treasury for protocol fees
    address public treasury;
    
    // Owner for admin functions
    address public owner;
    
    // Authorized anchorers (optional restriction)
    mapping(address => bool) public authorizedAnchorers;
    bool public restrictAnchoring = false;
    
    // ========================================================================
    // Events
    // ========================================================================
    
    event ThreadAnchored(
        bytes32 indexed threadId,
        bytes32 merkleRoot,
        uint64 hopCount,
        bytes32 intentHash,
        bool compliant,
        uint256 timestamp,
        address indexed anchorer
    );
    
    event BatchAnchored(
        bytes32 indexed batchId,
        bytes32 merkleRoot,
        uint64 threadCount,
        uint256 timestamp,
        address indexed anchorer
    );
    
    event ViolationRecorded(
        bytes32 indexed threadId,
        bytes32 indexed violationId,
        uint8 violationType,
        uint8 severity,
        uint256 timestamp,
        address indexed reporter
    );
    
    event ViolationResolved(
        bytes32 indexed threadId,
        bytes32 indexed violationId,
        bytes32 resolutionHash,
        uint256 timestamp,
        address indexed resolver
    );
    
    event TreasuryUpdated(address oldTreasury, address newTreasury);
    event OwnershipTransferred(address oldOwner, address newOwner);
    
    // ========================================================================
    // Modifiers
    // ========================================================================
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    modifier canAnchor() {
        if (restrictAnchoring) {
            require(authorizedAnchorers[msg.sender], "Not authorized");
        }
        _;
    }
    
    // ========================================================================
    // Constructor
    // ========================================================================
    
    constructor(address _treasury) {
        owner = msg.sender;
        treasury = _treasury;
    }
    
    // ========================================================================
    // Core Functions
    // ========================================================================
    
    /**
     * @notice Anchor a thread to Ethereum
     * @param threadId Unique thread identifier
     * @param merkleRoot Merkle root of all hop signatures
     * @param hopCount Number of hops in the thread
     * @param intentHash Hash of the original intent
     * @param compliant Whether the thread is compliant
     */
    function anchorThread(
        bytes32 threadId,
        bytes32 merkleRoot,
        uint64 hopCount,
        bytes32 intentHash,
        bool compliant
    ) external payable canAnchor {
        require(threadAnchors[threadId].timestamp == 0, "Thread already anchored");
        
        threadAnchors[threadId] = ThreadAnchor({
            merkleRoot: merkleRoot,
            hopCount: hopCount,
            intentHash: intentHash,
            compliant: compliant,
            timestamp: block.timestamp,
            anchorer: msg.sender
        });
        
        // Transfer any payment to treasury (voluntary protocol fee)
        if (msg.value > 0) {
            payable(treasury).transfer(msg.value);
        }
        
        emit ThreadAnchored(
            threadId,
            merkleRoot,
            hopCount,
            intentHash,
            compliant,
            block.timestamp,
            msg.sender
        );
    }
    
    /**
     * @notice Anchor a batch of threads
     * @param batchId Unique batch identifier
     * @param merkleRoot Merkle root of all thread anchors in batch
     * @param threadCount Number of threads in batch
     */
    function anchorBatch(
        bytes32 batchId,
        bytes32 merkleRoot,
        uint64 threadCount
    ) external payable canAnchor {
        require(batchAnchors[batchId].timestamp == 0, "Batch already anchored");
        
        batchAnchors[batchId] = BatchAnchor({
            merkleRoot: merkleRoot,
            threadCount: threadCount,
            timestamp: block.timestamp,
            anchorer: msg.sender
        });
        
        if (msg.value > 0) {
            payable(treasury).transfer(msg.value);
        }
        
        emit BatchAnchored(
            batchId,
            merkleRoot,
            threadCount,
            block.timestamp,
            msg.sender
        );
    }
    
    /**
     * @notice Record a violation
     * @param threadId Thread that violated policy
     * @param violationType Type of violation
     * @param severity Severity level (1-5)
     * @param descriptionHash Hash of violation description
     */
    function recordViolation(
        bytes32 threadId,
        uint8 violationType,
        uint8 severity,
        bytes32 descriptionHash
    ) external {
        require(severity >= 1 && severity <= 5, "Invalid severity");
        
        bytes32 violationId = keccak256(abi.encodePacked(
            threadId,
            violationCounts[threadId]
        ));
        
        violations[violationId] = Violation({
            threadId: threadId,
            violationType: violationType,
            severity: severity,
            descriptionHash: descriptionHash,
            timestamp: block.timestamp,
            reporter: msg.sender,
            resolved: false,
            resolutionHash: bytes32(0),
            resolvedAt: 0,
            resolver: address(0)
        });
        
        violationCounts[threadId]++;
        
        emit ViolationRecorded(
            threadId,
            violationId,
            violationType,
            severity,
            block.timestamp,
            msg.sender
        );
    }
    
    /**
     * @notice Resolve a violation
     * @param violationId Violation to resolve
     * @param resolutionHash Hash of resolution details
     */
    function resolveViolation(
        bytes32 violationId,
        bytes32 resolutionHash
    ) external {
        Violation storage v = violations[violationId];
        require(v.timestamp > 0, "Violation not found");
        require(!v.resolved, "Already resolved");
        
        v.resolved = true;
        v.resolutionHash = resolutionHash;
        v.resolvedAt = block.timestamp;
        v.resolver = msg.sender;
        
        emit ViolationResolved(
            v.threadId,
            violationId,
            resolutionHash,
            block.timestamp,
            msg.sender
        );
    }
    
    // ========================================================================
    // View Functions
    // ========================================================================
    
    /**
     * @notice Verify a thread anchor
     * @param threadId Thread to verify
     * @param expectedMerkleRoot Expected merkle root
     * @return valid Whether anchor exists and matches
     * @return timestamp When it was anchored
     */
    function verifyAnchor(
        bytes32 threadId,
        bytes32 expectedMerkleRoot
    ) external view returns (bool valid, uint256 timestamp) {
        ThreadAnchor memory anchor = threadAnchors[threadId];
        return (
            anchor.merkleRoot == expectedMerkleRoot && anchor.timestamp > 0,
            anchor.timestamp
        );
    }
    
    /**
     * @notice Get thread anchor details
     * @param threadId Thread to query
     */
    function getThreadAnchor(bytes32 threadId) external view returns (
        bytes32 merkleRoot,
        uint64 hopCount,
        bytes32 intentHash,
        bool compliant,
        uint256 timestamp,
        address anchorer
    ) {
        ThreadAnchor memory anchor = threadAnchors[threadId];
        return (
            anchor.merkleRoot,
            anchor.hopCount,
            anchor.intentHash,
            anchor.compliant,
            anchor.timestamp,
            anchor.anchorer
        );
    }
    
    /**
     * @notice Check if a thread is anchored
     * @param threadId Thread to check
     */
    function isAnchored(bytes32 threadId) external view returns (bool) {
        return threadAnchors[threadId].timestamp > 0;
    }
    
    // ========================================================================
    // Admin Functions
    // ========================================================================
    
    function setTreasury(address _treasury) external onlyOwner {
        emit TreasuryUpdated(treasury, _treasury);
        treasury = _treasury;
    }
    
    function transferOwnership(address newOwner) external onlyOwner {
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
    
    function setAuthorizedAnchorer(address anchorer, bool authorized) external onlyOwner {
        authorizedAnchorers[anchorer] = authorized;
    }
    
    function setRestrictAnchoring(bool restrict) external onlyOwner {
        restrictAnchoring = restrict;
    }
    
    function setProtocolFeeBps(uint256 _feeBps) external onlyOwner {
        require(_feeBps <= 1000, "Fee too high"); // Max 10%
        protocolFeeBps = _feeBps;
    }
}

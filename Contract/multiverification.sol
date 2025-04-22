// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

contract Verification {
    // -------------------- State Variables -------------------- //
    address public owner;
    uint16 public count_Exporters = 0;
    uint16 public count_hashes = 0;

    // Each document needs at least 2 confirmations
    uint public requiredConfirmations = 2;

    constructor() {
        owner = msg.sender;
    }

    struct Record {
        bytes32 docHash;       // The document's hash
        uint blockNumber;      // Block when the record was added
        uint minetime;         // Timestamp when added
        string info;           // The Exporter's info
        string ipfs_hash;      // IPFS CID of the document
        address exporter;      // The address that submitted the document
        uint confirmations;    // How many verifiers have approved this doc
        bool verified;         // True once confirmations >= requiredConfirmations
        bool denied;           // True if the doc was denied
    }

    struct Exporter_Record {
        uint blockNumber;
        string info;
    }

    // -------------------- Mappings -------------------- //
    // Document hash => Record details
    mapping(bytes32 => Record) private docHashes;
    // Exporter address => Exporter details
    mapping(address => Exporter_Record) private Exporters;

    // For each exporter, store an array of verifiers authorized to confirm/deny that exporter’s documents
    mapping(address => address[]) public exporterVerifiers;

    // For each document, track which verifiers have already confirmed it
    mapping(bytes32 => mapping(address => bool)) public hasConfirmed;

    // -------------------- Events -------------------- //

    /**
     * @dev Emitted when a document is added (pending verification).
     * Includes docHash as an indexed parameter, so you can read it in the event logs.
     */
    event addHash(
        address indexed _exporter,
        bytes32 indexed _docHash,
        string _ipfsHash
    );

    event DocumentPending(bytes32 indexed docHash, address exporter);
    event DocumentConfirmed(bytes32 indexed docHash, address verifier, uint confirmations);
    event DocumentVerified(bytes32 indexed docHash);

    /**
     * @dev Emitted when a document is denied.
     * Contains the docHash and the verifier who denied it.
     */
    event DocDenied(bytes32 indexed docHash, address indexed verifier);

    // -------------------- Modifiers -------------------- //
    modifier onlyOwner() {
        require(msg.sender == owner, "Caller is not the owner");
        _;
    }

    modifier validAddress(address _addr) {
        require(_addr != address(0), "Invalid address");
        _;
    }

    modifier authorised_Exporter(bytes32 _doc) {
        // Check that the caller’s info matches the doc’s info
        require(
            keccak256(abi.encodePacked(Exporters[msg.sender].info)) ==
            keccak256(abi.encodePacked(docHashes[_doc].info)),
            "Caller is not authorised to edit this document"
        );
        _;
    }

    modifier canAddHash() {
        require(Exporters[msg.sender].blockNumber != 0, "Caller not authorised to add documents");
        _;
    }

    // -------------------- Owner Functions -------------------- //

    function changeOwner(address _newOwner) public onlyOwner validAddress(_newOwner) {
        owner = _newOwner;
    }

    // -------------------- Exporter Management -------------------- //

    function add_Exporter(address _add, string calldata _info) external onlyOwner {
        require(Exporters[_add].blockNumber == 0, "Exporter already exists");
        Exporters[_add].blockNumber = block.number;
        Exporters[_add].info = _info;
        count_Exporters++;
    }

    function delete_Exporter(address _add) external onlyOwner {
        require(Exporters[_add].blockNumber != 0, "Exporter does not exist");
        Exporters[_add].blockNumber = 0;
        Exporters[_add].info = "";
        count_Exporters--;
    }

    function alter_Exporter(address _add, string calldata _newInfo) public onlyOwner {
        require(Exporters[_add].blockNumber != 0, "Exporter does not exist");
        Exporters[_add].info = _newInfo;
    }

    function getExporterInfo(address _add) external view returns (string memory) {
        return Exporters[_add].info;
    }

    // -------------------- Verifier Management (Per-Exporter) -------------------- //

    /**
     * @notice An exporter can add a verifier who can confirm or deny that exporter’s documents.
     */
    function addVerifierForExporter(address _verifier) external {
        require(Exporters[msg.sender].blockNumber != 0, "Only a registered exporter can add verifiers");
        require(_verifier != address(0), "Invalid verifier address");

        address[] storage verifiers = exporterVerifiers[msg.sender];
        for (uint i = 0; i < verifiers.length; i++) {
            require(verifiers[i] != _verifier, "Verifier already added");
        }
        verifiers.push(_verifier);
    }

    /**
     * @notice An exporter can remove one of their verifiers.
     */
    function removeVerifierForExporter(address _verifier) external {
        require(Exporters[msg.sender].blockNumber != 0, "Only a registered exporter can remove verifiers");
        address[] storage verifiers = exporterVerifiers[msg.sender];

        uint index = verifiers.length; // invalid index
        for (uint i = 0; i < verifiers.length; i++) {
            if (verifiers[i] == _verifier) {
                index = i;
                break;
            }
        }
        require(index < verifiers.length, "Verifier not found");
        verifiers[index] = verifiers[verifiers.length - 1];
        verifiers.pop();
    }

    /**
     * @dev Helper function to check if `verifier` is in the exporter’s verifier list
     */
    function isAuthorizedVerifier(address exporter, address verifier) public view returns (bool) {
        address[] storage verifiers = exporterVerifiers[exporter];
        for (uint i = 0; i < verifiers.length; i++) {
            if (verifiers[i] == verifier) {
                return true;
            }
        }
        return false;
    }

    // -------------------- Document Upload & Multi-Sig Verification -------------------- //

    /**
     * @notice Exporter uploads a document hash with its IPFS CID.
     * The document remains unverified until enough verifiers confirm it.
     */
    function addDocHash(bytes32 hash, string calldata _ipfs) public canAddHash {
        // Ensure doc not already added
        require(docHashes[hash].blockNumber == 0 && docHashes[hash].minetime == 0, "Document already exists");

        docHashes[hash] = Record({
            docHash: hash,
            blockNumber: block.number,
            minetime: block.timestamp,
            info: Exporters[msg.sender].info,
            ipfs_hash: _ipfs,
            exporter: msg.sender,
            confirmations: 0,
            verified: false,
            denied: false
        });

        // Don’t increment count_hashes yet (only after verification)
        emit addHash(msg.sender, hash, _ipfs);
        emit DocumentPending(hash, msg.sender);
    }

    /**
     * @notice An authorized verifier confirms a document. 
     * Once confirmations >= requiredConfirmations, it’s marked verified and count_hashes increments.
     */
    function confirmDocHash(bytes32 hash) external {
        Record storage doc = docHashes[hash];
        require(doc.blockNumber != 0 && doc.minetime != 0, "Document does not exist");
        require(!doc.verified, "Document already verified");
        require(!doc.denied, "Document is denied, cannot confirm");
        require(isAuthorizedVerifier(doc.exporter, msg.sender), "Caller is not an authorized verifier");
        require(!hasConfirmed[hash][msg.sender], "Already confirmed by this verifier");

        hasConfirmed[hash][msg.sender] = true;
        doc.confirmations++;

        emit DocumentConfirmed(hash, msg.sender, doc.confirmations);

        // If enough verifiers have confirmed, mark it verified
        if (doc.confirmations >= requiredConfirmations) {
            doc.verified = true;
            count_hashes++;
            emit DocumentVerified(hash);
        }
    }

    /**
     * @notice Deny a document. 
     * This sets `denied = true`, preventing further confirmation or final verification.
     * Only an authorized verifier can deny a doc, and it must not be already verified or denied.
     */
    function denyDocHash(bytes32 hash) external {
        Record storage doc = docHashes[hash];
        require(doc.blockNumber != 0 && doc.minetime != 0, "Document does not exist");
        require(!doc.verified, "Document already verified");
        require(!doc.denied, "Document already denied");
        require(isAuthorizedVerifier(doc.exporter, msg.sender), "Caller is not an authorized verifier");

        doc.denied = true;
        emit DocDenied(hash, msg.sender);
    }

    /**
     * @notice Delete a document hash (only the original exporter).
     * If you want to prevent deleting verified docs, add a `require(!doc.verified)` here.
     */
    function deleteHash(bytes32 _hash) public authorised_Exporter(_hash) canAddHash {
        require(docHashes[_hash].minetime != 0, "Document does not exist");
        
        // Optional: require(!docHashes[_hash].verified, "Cannot delete a verified document");

        // Clear the record
        docHashes[_hash].docHash = 0x0;
        docHashes[_hash].blockNumber = 0;
        docHashes[_hash].minetime = 0;
        docHashes[_hash].ipfs_hash = "";
        docHashes[_hash].exporter = address(0);
        docHashes[_hash].confirmations = 0;
        docHashes[_hash].verified = false;
        docHashes[_hash].denied = false;
        // If it was verified, you might decrement count_hashes here (depending on your logic)
    }

    // -------------------- Views -------------------- //

    /**
     * @notice Return docHash details including confirmations & verified status.
     */
    function findDocHash(bytes32 _hash)
        external
        view
        returns (
            bytes32 doc_Hash,
            uint blockNo,
            uint timeStamp,
            string memory exporterInfo,
            string memory ipfsHash,
            address docExporter,
            uint confirmations,
            bool isVerified,
            bool isDenied
        )
    {
        Record memory r = docHashes[_hash];
        return (
            r.docHash,
            r.blockNumber,
            r.minetime,
            r.info,
            r.ipfs_hash,
            r.exporter,
            r.confirmations,
            r.verified,
            r.denied
        );
    }
}

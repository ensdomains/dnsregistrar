pragma solidity ^0.5.0;

import "@ensdomains/dnssec-oracle/contracts/BytesUtils.sol";
import "@ensdomains/dnssec-oracle/contracts/DNSSEC.sol";
import "@ensdomains/ens/contracts/ENSRegistry.sol";
import "@ensdomains/root/contracts/Root.sol";
import "./DNSClaimChecker.sol";
import "./PublicSuffixList.sol";

/**
 * @dev An ENS registrar that allows the owner of a DNS name to claim the
 *      corresponding name in ENS.
 */
contract DNSRegistrar {
    using BytesUtils for bytes;

    DNSSEC public oracle;
    ENS public ens;
    PublicSuffixList public suffixes;

    bytes4 constant private INTERFACE_META_ID = bytes4(keccak256("supportsInterface(bytes4)"));
    bytes4 constant private DNSSEC_CLAIM_ID = bytes4(
        keccak256("claim(bytes,bytes)") ^
        keccak256("proveAndClaim(bytes,bytes,bytes)") ^
        keccak256("oracle()")
    );

    event Claim(bytes32 indexed node, address indexed owner, bytes dnsname);
    event NewOracle(address oracle);
    event NewPublicSuffixList(address suffixes);
    event NewSuffix(bytes suffix);

    constructor(DNSSEC _dnssec, PublicSuffixList _suffixes, ENS _ens) public {
        oracle = _dnssec;
        emit NewOracle(address(oracle));
        suffixes = _suffixes;
        emit NewPublicSuffixList(address(suffixes));
        ens = _ens;
    }

    /**
     * @dev This contract's owner-only functions can be invoked by the owner of the ENS root.
     */
    modifier onlyOwner {
        Root root = Root(ens.owner(bytes32(0)));
        address owner = root.owner();
        require(msg.sender == owner);
        _;
    }

    function setOracle(DNSSEC _dnssec) public onlyOwner {
        oracle = _dnssec;
        emit NewOracle(address(oracle));
    }

    function setPublicSuffixList(PublicSuffixList _suffixes) public onlyOwner {
        suffixes = _suffixes;
        emit NewPublicSuffixList(address(suffixes));
    }

    /**
     * @dev Claims a name by proving ownership of its DNS equivalent.
     * @param name The name to claim, in DNS wire format.
     * @param proof A DNS RRSet proving ownership of the name. Must be verified
     *        in the DNSSEC oracle before calling. This RRSET must contain a TXT
     *        record for '_ens.' + name, with the value 'a=0x...'. Ownership of
     *        the name will be transferred to the address specified in the TXT
     *        record.
     */
    function claim(bytes memory name, bytes memory proof) public {
        // Parent name must be in the public suffix list.
        uint labelLen = name.readUint8(0);
        require(suffixes.isPublicSuffix(name.substring(labelLen + 1, name.length - labelLen - 1)), "Parent name must be a public suffix");

        address addr;
        (addr,) = DNSClaimChecker.getOwnerAddress(oracle, name, proof);

        bytes32 labelHash;
        bytes32 rootNode;
        (labelHash, rootNode) = DNSClaimChecker.getLabels(name);

        ens.setSubnodeOwner(rootNode, labelHash, addr);
        emit Claim(keccak256(abi.encodePacked(rootNode, labelHash)), addr, name);
    }

    /**
     * @dev Submits proofs to the DNSSEC oracle, then claims a name using those proofs.
     * @param name The name to claim, in DNS wire format.
     * @param input The data to be passed to the Oracle's `submitProofs` function. The last
     *        proof must be the TXT record required by the registrar.
     * @param proof The proof record for the first element in input.
     */
    function proveAndClaim(bytes memory name, bytes memory input, bytes memory proof) public {
        proof = oracle.submitRRSets(input, proof);
        claim(name, proof);
    }

    function enableSuffix(bytes memory domain) public {
        require(suffixes.isPublicSuffix(domain), "Domain must be a public suffix");
        (, bool enabled) = claimNode(domain, 0);
        require(enabled, "Domain must not already be enabled");
        emit NewSuffix(domain);
    }

    function supportsInterface(bytes4 interfaceID) external pure returns (bool) {
        return interfaceID == INTERFACE_META_ID ||
               interfaceID == DNSSEC_CLAIM_ID;
    }

    function claimNode(bytes memory domain, uint offset) internal returns(bytes32 node, bool enabled) {
        uint len = domain.readUint8(offset);
        if(len == 0) {
            return (bytes32(0), false);
        }

        (bytes32 parentNode,) = claimNode(domain, offset + len + 1);
        bytes32 label = domain.keccak(offset + 1, len);
        node = keccak256(abi.encodePacked(parentNode, label));
        address owner = ens.owner(node);
        require(owner == address(0) || owner == address(this), "Cannot claim a name owned by someone else");
        if(owner != address(this)) {
            if(parentNode == bytes32(0)) {
                Root root = Root(ens.owner(bytes32(0)));
                root.setSubnodeOwner(label, address(this));
            } else {
                ens.setSubnodeOwner(parentNode, label, address(this));
            }
            return (node, true);
        }
        return (node, false);
    }
}

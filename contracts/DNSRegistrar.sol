pragma solidity ^0.4.23;

import "@ensdomains/ens/contracts/ENSRegistry.sol";
import "@ensdomains/dnssec-oracle/contracts/DNSSEC.sol";
import "./DNSClaimChecker.sol";

/**
 * @dev An ENS registrar that allows the owner of a DNS name to claim the
 *      corresponding name in ENS.
 */
contract DNSRegistrar {

    DNSSEC public oracle;
    ENS public ens;

    event Claim(bytes32 indexed node, address indexed owner, bytes dnsname);

    constructor(DNSSEC _dnssec, ENS _ens) public {
        oracle = _dnssec;
        ens = _ens;
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
    function claim(bytes name, bytes proof) public {
        address addr = DNSClaimChecker.getOwnerAddress(oracle, name, proof);

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
    function proveAndClaim(bytes name, bytes input, bytes proof) public {
        proof = oracle.submitRRSets(input, proof);
        claim(name, proof);
    }
}

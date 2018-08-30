pragma solidity ^0.4.23;

import "@ensdomains/ens/contracts/ENSRegistry.sol";
import "@ensdomains/dnssec-oracle/contracts/DNSSEC.sol";
import "@ensdomains/dnssec-oracle/contracts/BytesUtils.sol";
import "@ensdomains/dnssec-oracle/contracts/RRUtils.sol";

/**
 * @dev An ENS registrar that allows the owner of a DNS name to claim the
 *      corresponding name in ENS.
 */
contract DNSRegistrar {
    using BytesUtils for bytes;
    using RRUtils for *;
    using Buffer for Buffer.buffer;

    uint16 constant CLASS_INET = 1;
    uint16 constant TYPE_TXT = 16;

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
        address addr = getOwnerAddress(name, proof);

        bytes32 labelHash;
        bytes32 rootNode;
        (labelHash, rootNode) = getLabels(name);
        
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

    function getLabels(bytes memory name) internal view returns (bytes32, bytes32) {
        uint len = name.readUint8(0);
        uint second = name.readUint8(len + 1);

        require(name.readUint8(len + second + 2) == 0);

        return (name.keccak(1, len), keccak256(bytes32(0), name.keccak(2 + len, second)));
    }

    function getOwnerAddress(bytes memory name, bytes memory proof) internal view returns(address) {
        // Add "_ens." to the front of the name.
        Buffer.buffer memory buf;
        buf.init(name.length + 5);
        buf.append("\x04_ens");
        buf.append(name);
        bytes20 hash;
        uint64 inserted;
        // Check the provided TXT record has been validated by the oracle
        (, inserted, hash) = oracle.rrdata(TYPE_TXT, buf.buf);
        if(hash == bytes20(0) && proof.length == 0) return 0;

        require(hash == bytes20(keccak256(proof)));

        for(RRUtils.RRIterator memory iter = proof.iterateRRs(0); !iter.done(); iter.next()) {
            require(inserted + iter.ttl >= now, "DNS record is stale; refresh or delete it before proceeding.");

            address addr = parseRR(proof, iter.rdataOffset);
            if(addr != 0) {
                return addr;
            }
        }

        return 0;
    }

    function parseRR(bytes memory rdata, uint idx) internal pure returns(address) {
        while(idx < rdata.length) {
            uint len = rdata.readUint8(idx); idx += 1;
            address addr = parseString(rdata, idx, len);
            if(addr != 0) return addr;
            idx += len;
        }

        return 0;
    }

    function parseString(bytes memory str, uint idx, uint len) internal pure returns(address) {
        // TODO: More robust parsing that handles whitespace and multiple key/value pairs
        if(str.readUint32(idx) != 0x613d3078) return 0; // 0x613d3078 == 'a=0x'
        if(len < 44) return 0;
        return hexToAddress(str, idx + 4);
    }

    function hexToAddress(bytes memory str, uint idx) internal pure returns(address) {
        if(str.length - idx < 40) return 0;
        uint ret = 0;
        for(uint i = idx; i < idx + 40; i++) {
            ret <<= 4;
            uint x = str.readUint8(i);
            if(x >= 48 && x < 58) {
                ret |= x - 48;
            } else if(x >= 65 && x < 71) {
                ret |= x - 55;
            } else if(x >= 97 && x < 103) {
                ret |= x - 87;
            } else {
                return 0;
            }
        }
        return address(ret);
    }
}

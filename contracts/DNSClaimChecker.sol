pragma solidity ^0.4.24;

import "@ensdomains/dnssec-oracle/contracts/DNSSEC.sol";
import "@ensdomains/dnssec-oracle/contracts/BytesUtils.sol";
import "@ensdomains/dnssec-oracle/contracts/RRUtils.sol";
import "@ensdomains/buffer/contracts/Buffer.sol";

library DNSClaimChecker {

    using BytesUtils for bytes;
    using RRUtils for *;
    using Buffer for Buffer.buffer;

    uint16 constant CLASS_INET = 1;
    uint16 constant TYPE_TXT = 16;

    function getLabels(bytes memory name) internal view returns (bytes32, bytes32) {
        uint len = name.readUint8(0);
        uint second = name.readUint8(len + 1);

        require(name.readUint8(len + second + 2) == 0);

        return (name.keccak(1, len), keccak256(bytes32(0), name.keccak(2 + len, second)));
    }

    function getOwnerAddress(DNSSEC oracle, bytes memory name, bytes memory proof, address defaultAddr)
        internal
        view
        returns (address)
    {
        // Add "_ens." to the front of the name.
        Buffer.buffer memory buf;
        buf.init(name.length + 5);
        buf.append("\x04_ens");
        buf.append(name);
        bytes20 hash;
        uint64 inserted;
        // Check the provided TXT record has been validated by the oracle
        (, inserted, hash) = oracle.rrdata(TYPE_TXT, buf.buf);
        if (hash == bytes20(0) && proof.length == 0) return defaultAddr;

        require(hash == bytes20(keccak256(proof)));

        for (RRUtils.RRIterator memory iter = proof.iterateRRs(0); !iter.done(); iter.next()) {
            require(inserted + iter.ttl >= now, "DNS record is stale; refresh or delete it before proceeding.");

            address addr = parseRR(proof, iter.rdataOffset, defaultAddr);
            if (addr != 0) {
                return addr;
            }
        }

        return 0;
    }

    function parseRR(bytes memory rdata, uint idx, address defaultAddr) internal pure returns (address) {
        bool didError = false;

        while (idx < rdata.length) {
            uint len = rdata.readUint8(idx); idx += 1;

            bool succeeded;
            address addr;
            (addr, succeeded) = parseString(rdata, idx, len);

            if (!succeeded) {
                didError = true;
            }

            if (addr != 0) return addr;
            idx += len;
        }

        if (didError) return defaultAddr;
        return 0x0;
    }

    function parseString(bytes memory str, uint idx, uint len) internal pure returns (address, bool) {
        // TODO: More robust parsing that handles whitespace and multiple key/value pairs
        if (str.readUint32(idx) != 0x613d3078) return (0, true); // 0x613d3078 == 'a=0x'
        if (len < 44) return (0, true);
        return hexToAddress(str, idx + 4);
    }

    function hexToAddress(bytes memory str, uint idx) internal pure returns (address, bool) {
        if (str.length - idx < 40) return (0, false);
        uint ret = 0;
        for (uint i = idx; i < idx + 40; i++) {
            ret <<= 4;
            uint x = str.readUint8(i);
            if (x >= 48 && x < 58) {
                ret |= x - 48;
            } else if (x >= 65 && x < 71) {
                ret |= x - 55;
            } else if (x >= 97 && x < 103) {
                ret |= x - 87;
            } else {
                return (0, false);
            }
        }
        return (address(ret), true);
    }

}

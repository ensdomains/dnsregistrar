pragma solidity ^0.4.17;

import "./ens.sol";
import "./dnssec.sol";
import "./bytesutils.sol";
import "./rrutils.sol";

/**
 * @dev An ENS registrar that allows the owner of a DNS name to claim the
 *      corresponding name in ENS.
 */
contract DNSRegistrar {
    using BytesUtils for *;
    using RRUtils for *;

    uint16 constant CLASS_INET = 1;
    uint16 constant TYPE_TXT = 16;

    DNSSEC public oracle;
    ENS public ens;
    bytes public rootDomain;
    bytes32 public rootNode;

    function DNSRegistrar(DNSSEC _dnssec, ENS _ens, bytes _rootDomain, bytes32 _rootNode) public {
        oracle = _dnssec;
        ens = _ens;
        rootDomain = _rootDomain;
        rootNode = _rootNode;
    }

    function claim(bytes name) public {
        var nameslice = name.toSlice();

        var labelHash = getLabelHash(nameslice);
        require(labelHash != 0);

        var addr = getOwnerAddress(nameslice);
        // Anyone can set the address to 0, but only the owner can claim a name.
        require(addr == 0 || addr == msg.sender);

        ens.setSubnodeOwner(rootNode, labelHash, addr);
    }

    function getLabelHash(BytesUtils.slice memory name) internal constant returns(bytes32) {
        var len = name.uint8At(0);
        // Check this name is a direct subdomain of the one we're responsible for
        if(name.keccak(len + 1, name.len) != keccak256(rootDomain)) {
            return 0;
        }
        return name.keccak(1, len + 1);
    }

    function getOwnerAddress(BytesUtils.slice memory name) internal constant returns(address) {
        // Add "_ens." to the front of the name.
        var subname = BytesUtils.newSlice(name.len + 5);
        subname.writeBytes(0, "\x04_ens");
        subname.memcpy(5, name, 0, name.len);

        // Query the oracle for TXT records
        var rrs = getTXT(subname);

        BytesUtils.slice memory rrname;
        BytesUtils.slice memory rdata;
        for(var (dnstype,,) = rrs.nextRR(rrname, rdata); dnstype != 0; (dnstype,,) = rrs.nextRR(name, rdata)) {
            var addr = parseRR(rdata);
            if(addr != 0) return addr;
        }

        return 0;
    }

    function getTXT(BytesUtils.slice memory name) internal constant returns(BytesUtils.slice memory) {
        uint len;
        uint ptr;
        oracle.rrset(CLASS_INET, TYPE_TXT, name.toBytes());
        assembly {
            // Fetch the pointer to the RR data
            returndatacopy(0, 0x60, 0x20)
            ptr := mload(0)
            // Fetch the RR data length
            returndatacopy(0, ptr, 0x20)
            len := mload(0)
        }
        // Allocate space for the RR data
        var ret = BytesUtils.newSlice(len);
        assembly {
            // Fetch the RR data
            returndatacopy(mload(add(ret, 0x20)), add(ptr, 0x20), len)
        }
        return ret;
    }

    function parseRR(BytesUtils.slice memory rdata) internal pure returns(address) {
        BytesUtils.slice memory segment;

        uint idx = 0;
        var len = rdata.uint8At(idx);
        while(len + idx <= rdata.len) {
            segment._ptr = rdata._ptr + idx + 1;
            segment.len = len;
            var addr = parseString(segment);
            if(addr != 0) return addr;
        }

        return 0;
    }

    function parseString(BytesUtils.slice memory str) internal pure returns(address) {
        // TODO: More robust parsing that handles whitespace and multiple key/value pairs
        if(str.uint32At(0) != 0x613d3078) return 0; // 0x613d3078 == 'a=0x'
        str.s(4, str.len);
        return hexToAddress(str);
    }

    function hexToAddress(BytesUtils.slice memory str) internal pure returns(address) {
        if(str.len < 40) return 0;
        uint ret = 0;
        for(uint i = 0; i < 40; i++) {
            ret <<= 4;
            var x = str.uint8At(i);
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

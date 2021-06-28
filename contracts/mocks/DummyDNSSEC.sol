pragma solidity ^0.7.0;
pragma experimental ABIEncoderV2;

contract DummyDNSSEC {
    uint16 expectedType;
    bytes expectedName;
    uint32 inception;
    uint64 inserted;
    bytes20 hash;

    struct RRSetWithSignature {
        bytes rrset;
        bytes sig;
    }

    function setData(uint16 _expectedType, bytes memory _expectedName, uint32 _inception, uint64 _inserted, bytes memory _proof) public {
        expectedType = _expectedType;
        expectedName = _expectedName;
        inception = _inception;
        inserted = _inserted;
        if(_proof.length != 0) {
            hash = bytes20(keccak256(_proof));
        }
    }

    function submitRRSets(RRSetWithSignature[] memory input, bytes memory proof) public returns (bytes memory) {
        if(input.length > 0) {
            return input[input.length - 1].rrset;
        } else {
            return proof;
        }
    }

    function rrdata(uint16 dnstype, bytes memory name) public view returns (uint32, uint64, bytes20) {
        require(dnstype == expectedType);
        require(keccak256(name) == keccak256(expectedName));
        return (inception, inserted, hash);
    }
}

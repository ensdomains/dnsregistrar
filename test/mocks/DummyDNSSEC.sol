pragma solidity ^0.5.0;

contract DummyDNSSEC {
    uint16 expectedType;
    bytes expectedName;
    bytes20 hash;
    uint32 expiration;
    uint32 inception;

    function setData(uint16 _expectedType, bytes memory _expectedName, bytes memory _proof, uint32 _expiration, uint32 _inception) public {
        expectedType = _expectedType;
        expectedName = _expectedName;
        if(_proof.length != 0) {
            hash = bytes20(keccak256(_proof));
        }
        expiration = _expiration;
        inception = _inception;
    }

    function rrdata(uint16 dnstype, bytes memory name) public view returns (bytes20, uint32, uint32) {
        require(dnstype == expectedType);
        require(keccak256(name) == keccak256(expectedName));
        return (hash, expiration, inception);
    }
}

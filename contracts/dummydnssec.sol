pragma solidity ^0.4.17;

contract DummyDNSSEC {
    uint16 expectedType;
    bytes expectedName;
    uint32 inception;
    uint64 inserted;
    bytes rrs;

    function setData(uint16 _expectedType, bytes _expectedName, uint32 _inception, uint64 _inserted, bytes _rrs) public {
      expectedType = _expectedType;
      expectedName = _expectedName;
      inception = _inception;
      inserted = _inserted;
      rrs = _rrs;
    }

    function rrset(uint16 class, uint16 dnstype, bytes name) public constant returns(uint32, uint64, bytes) {
        require(class == 1);
        require(dnstype == expectedType);
        require(keccak256(name) == keccak256(expectedName));
        return (inception, inserted, rrs);
    }
}

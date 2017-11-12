pragma solidity ^0.4.17;

contract DNSSEC {
    function rrset(uint16 class, uint16 dnstype, bytes name) public constant returns(uint32 inception, uint32 expiration, uint64 inserted, bytes rrs);
}

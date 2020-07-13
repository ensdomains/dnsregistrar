pragma solidity ^0.5.0;

interface PublicSuffixList {
    function isPublicSuffix(bytes calldata name) external view returns(bool);
}

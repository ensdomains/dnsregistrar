// Include ENSImplementation so that it gets compiled
var ENSImplementation = artifacts.require("./ENSImplementation.sol");
var DNSRegistrar = artifacts.require("./DNSRegistrar.sol");

var namehash = require('eth-ens-namehash');
var sha3 = require('js-sha3').keccak_256
var dns = require('../lib/dns.js');

module.exports = function(deployer, network, accounts) {
  if(network == "ropsten") {
    deployer.deploy(
      DNSRegistrar,
      "0xd7296B6044ffD0565062345c2EaA4017024B2D22",
      "0x112234455c3a32fd11230c42e7bccd4a84e02010",
      dns.hexEncodeName("xyz."),
      namehash.hash("xyz"));
  }
};

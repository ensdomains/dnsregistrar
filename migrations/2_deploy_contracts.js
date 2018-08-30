var ENSRegistry = artifacts.require("@ensdomains/ens/ENSRegistry");
var DummyDNSSEC = artifacts.require("./DummyDNSSEC");
var DNSRegistrar = artifacts.require("./DNSRegistrar.sol");

var namehash = require('eth-ens-namehash');
var sha3 = require('js-sha3').keccak_256
var dns = require('../lib/dns.js');
var tld = 'xyz'

module.exports = function(deployer, network, accounts) {
  if(network == "ropsten") {
    deployer.deploy(
      DNSRegistrar,
      "0xd7296B6044ffD0565062345c2EaA4017024B2D22",
      "0x112234455c3a32fd11230c42e7bccd4a84e02010",
      dns.hexEncodeName(tld + "."),
      namehash.hash(tld));
  }else{
    deployer.deploy([[ENSRegistry], [DummyDNSSEC]]).then(function() {
      return ENSRegistry.deployed().then(function(ens) {
        return DummyDNSSEC.deployed().then(function(dnssec) {
          return deployer.deploy(DNSRegistrar, dnssec.address, ens.address).then(function() {
            return DNSRegistrar.deployed().then(function(registrar) {
              return registrar.addRootDomain(dns.hexEncodeName(tld + "."), namehash.hash(tld)).then(function () {
                  return ens.setSubnodeOwner(0, "0x" + sha3(tld), registrar.address);
              })
            });
          });
        });
      });
    });
  }
};

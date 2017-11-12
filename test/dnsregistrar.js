var ENSImplementation = artifacts.require("./ENSImplementation.sol");
var DummyDNSSEC = artifacts.require("./DummyDNSSEC.sol");
var DNSRegistrar = artifacts.require("./DNSRegistrar.sol");

var namehash = require('eth-ens-namehash');
var dns = require("../lib/dns.js");

contract('DNSRegistrar', function(accounts) {
  var registrar = null;
  var ens = null;
  var dnssec = null;

  before(async function() {
    registrar = await DNSRegistrar.deployed();
    ens = await ENSImplementation.deployed();
    dnssec = await DummyDNSSEC.deployed();
  });

  it('allows the owner of a DNS name to claim it in ENS', async function() {
    assert.equal(await registrar.oracle(), dnssec.address);
    assert.equal(await registrar.ens(), ens.address);
    assert.equal(await registrar.rootDomain(), dns.hexEncodeName("test."));
    assert.equal(await registrar.rootNode(), namehash.hash("test"));

    var tx = await dnssec.setData(16, dns.hexEncodeName("_ens.foo.test."), 0, 0, 0, dns.hexEncodeTXT({
      name: "_ens.foo.test.",
      klass: 1,
      ttl: 3600,
      text: ["a=" + accounts[0]]
    }));
    assert.equal(tx.receipt.status, "0x1");

    tx = await registrar.claim(dns.hexEncodeName("foo.test."));
    assert.equal(tx.receipt.status, "0x1");

    assert.equal(await ens.owner(namehash.hash("foo.test")), accounts[0]);
  });

  it('allows anyone to zero out an obsolete name', async function() {
    var tx = await dnssec.setData(16, dns.hexEncodeName("_ens.foo.test."), 0, 0, 0, "");
    assert.equal(tx.receipt.status, "0x1");

    tx = await registrar.claim(dns.hexEncodeName("foo.test."));
    assert.equal(tx.receipt.status, "0x1");

    assert.equal(await ens.owner(namehash.hash("foo.test")), 0);
  });

  it('does not allow anyone but the owner to claim the name', async function() {
    var tx = await dnssec.setData(16, dns.hexEncodeName("_ens.foo.test."), 0, 0, 0, dns.hexEncodeTXT({
      name: "_ens.foo.test.",
      klass: 1,
      ttl: 3600,
      text: ["a=0x0123456789012345678901234567890123456789"]
    }));
    assert.equal(tx.receipt.status, "0x1");

    tx = await registrar.claim(dns.hexEncodeName("foo.test."));
    assert.equal(tx.receipt.status, "0x0");

    assert.equal(await ens.owner(namehash.hash("foo.test")), 0);
  });
});

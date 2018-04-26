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

    var now = Math.round(new Date().getTime() / 1000);
    var tx = await dnssec.setData(16, dns.hexEncodeName("_ens.foo.test."), now, now, dns.hexEncodeTXT({
      name: "_ens.foo.test.",
      klass: 1,
      ttl: 3600,
      text: ["a=" + accounts[0]]
    }));
    assert.equal(parseInt(tx.receipt.status), 1);

    tx = await registrar.claim(dns.hexEncodeName("foo.test."));
    assert.equal(parseInt(tx.receipt.status), 1);

    assert.equal(await ens.owner(namehash.hash("foo.test")), accounts[0]);
  });

  it('allows anyone to zero out an obsolete name', async function() {
    var now = Math.round(new Date().getTime() / 1000);
    var tx = await dnssec.setData(16, dns.hexEncodeName("_ens.foo.test."), now, now, "");
    assert.equal(parseInt(tx.receipt.status), 1);

    tx = await registrar.claim(dns.hexEncodeName("foo.test."));
    assert.equal(parseInt(tx.receipt.status), 1);

    assert.equal(await ens.owner(namehash.hash("foo.test")), 0);
  });

  it('does not allow anyone but the owner to claim the name', async function() {
    var now = Math.round(new Date().getTime() / 1000);
    var tx = await dnssec.setData(16, dns.hexEncodeName("_ens.foo.test."), now, now, dns.hexEncodeTXT({
      name: "_ens.foo.test.",
      klass: 1,
      ttl: 3600,
      text: ["a=0x0123456789012345678901234567890123456789"]
    }));
    assert.equal(parseInt(tx.receipt.status), 1);

    tx = undefined;
    try {
      tx = await registrar.claim(dns.hexEncodeName("foo.test."));
    } catch(error) {
      // Assert ganache revert exception
      assert.equal(error.message, 'VM Exception while processing transaction: revert');
    }
    // Assert geth failed transaction
    if(tx !== undefined) {
      assert.equal(parseInt(tx.receipt.status), 0);
    }

    assert.equal(await ens.owner(namehash.hash("foo.test")), 0);
  });

  it('does not allow updates with stale records', async function() {
    var tx = await dnssec.setData(16, dns.hexEncodeName("_ens.foo.test."), 0, 0, dns.hexEncodeTXT({
      name: "_ens.bar.test.",
      klass: 1,
      ttl: 3600,
      text: ["a=" + accounts[0]]
    }));
    assert.equal(parseInt(tx.receipt.status), 1);

    tx = undefined;
    try {
      tx = await registrar.claim(dns.hexEncodeName("bar.test."));
    } catch(error) {
      // Assert ganache revert exception
      assert.equal(error.message, 'VM Exception while processing transaction: revert');
    }
    // Assert geth failed transaction
    if(tx !== undefined) {
      assert.equal(parseInt(tx.receipt.status), 0);
    }

    assert.equal(await ens.owner(namehash.hash("bar.test")), 0);
  });
});

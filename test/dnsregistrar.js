var ENSImplementation = artifacts.require('./ENSImplementation.sol');
var DummyDNSSEC = artifacts.require('./DummyDNSSEC.sol');
var DNSRegistrarContract = artifacts.require('./DNSRegistrar.sol');
var namehash = require('eth-ens-namehash');
var dns = require('../lib/dns.js');
var sha3 = require('js-sha3').keccak_256;
var DnsProve = require('@ensdomains/dnsprovejs');
var sinon = require('sinon');
var DNSRegistrar = require('../lib/dnsregistrar');

contract('DNSRegistrar', function(accounts) {
  var registrar = null;
  var ens = null;
  var dnssec = null;
  var dnssecAddress = null;
  var tld = 'test';
  var now = Math.round(new Date().getTime() / 1000);

  beforeEach(async function() {
    ens = await ENSImplementation.new();
    dnssec = await DummyDNSSEC.new();
    registrar = await DNSRegistrarContract.new(
      dnssec.address,
      ens.address,
      dns.hexEncodeName(tld + '.'),
      namehash.hash(tld)
    );
    dnssecAddress = registrar.oracle.call();
    await ens.setSubnodeOwner(0, '0x' + sha3(tld), registrar.address);
  });

  it('allows the owner of a DNS name to claim it in ENS', async function() {
    assert.equal(await registrar.oracle(), dnssec.address);
    assert.equal(await registrar.ens(), ens.address);
    assert.equal(await registrar.rootDomain(), dns.hexEncodeName('test.'));
    assert.equal(await registrar.rootNode(), namehash.hash('test'));

    var proof = dns.hexEncodeTXT({
      name: '_ens.foo.test.',
      klass: 1,
      ttl: 3600,
      text: ['a=' + accounts[0]]
    });
    var tx = await dnssec.setData(
      16,
      dns.hexEncodeName('_ens.foo.test.'),
      now,
      now,
      proof
    );
    assert.equal(parseInt(tx.receipt.status), 1);

    tx = await registrar.claim(dns.hexEncodeName('foo.test.'), proof);
    assert.equal(parseInt(tx.receipt.status), 1);

    assert.equal(await ens.owner(namehash.hash('foo.test')), accounts[0]);
  });

  it('allows anyone to zero out an obsolete name', async function() {
    var tx = await dnssec.setData(
      16,
      dns.hexEncodeName('_ens.foo.test.'),
      now,
      now,
      ''
    );
    assert.equal(parseInt(tx.receipt.status), 1);

    tx = await registrar.claim(dns.hexEncodeName('foo.test.'), '');
    assert.equal(parseInt(tx.receipt.status), 1);

    assert.equal(await ens.owner(namehash.hash('foo.test')), 0);
  });

  it('allows anyone to update a DNSSEC referenced name', async function() {
    var proof = dns.hexEncodeTXT({
      name: '_ens.foo.test.',
      klass: 1,
      ttl: 3600,
      text: ['a=0x0123456789012345678901234567890123456789']
    });
    var tx = await dnssec.setData(
      16,
      dns.hexEncodeName('_ens.foo.test.'),
      now,
      now,
      proof
    );
    assert.equal(parseInt(tx.receipt.status), 1);

    tx = await registrar.claim(dns.hexEncodeName('foo.test.'), proof);
    assert.equal(parseInt(tx.receipt.status), 1);
    assert.equal(
      await ens.owner(namehash.hash('foo.test')),
      '0x0123456789012345678901234567890123456789'
    );
  });

  it('does not allow updates with stale records', async function() {
    var proof = dns.hexEncodeTXT({
      name: '_ens.bar.test.',
      klass: 1,
      ttl: 3600,
      text: ['a=' + accounts[0]]
    });
    var tx = await dnssec.setData(
      16,
      dns.hexEncodeName('_ens.foo.test.'),
      0,
      0,
      proof
    );
    assert.equal(parseInt(tx.receipt.status), 1);

    tx = undefined;
    try {
      tx = await registrar.claim(dns.hexEncodeName('bar.test.'), proof);
    } catch (error) {
      // Assert ganache revert exception
      assert.equal(
        error.message,
        'VM Exception while processing transaction: revert'
      );
    }
    // Assert geth failed transaction
    if (tx !== undefined) {
      assert.equal(parseInt(tx.receipt.status), 0);
    }

    assert.equal(await ens.owner(namehash.hash('bar.test')), 0);
  });

  describe('dnsregistrarjs.claim', async function() {
    var dnsProofs, provider, dnsprover, owner, nonOwner, proof, dnsregistrarjs;
    before(async function() {
      dnsProofs = 6;
      provider = web3.currentProvider;
      dnsprover = new DnsProve(provider);
      owner = accounts[1];
      nonOwner = accounts[2];
      proof = dns.hexEncodeTXT({
        name: '_ens.foo.test.',
        klass: 1,
        ttl: 3600,
        text: [`a=${owner}`]
      });
    });

    it('looks up DNS record, submits the proof to DNSSEC, and claims the name', async function() {
      sinon
        .stub(dnsprover, 'prove')
        .withArgs('_ens.foo.test', dnssec.address)
        .resolves({
          unproven: dnsProofs,
          lastProof: proof,
          owner: owner,
          submit: async () => {
            await dnssec.setData(
              16,
              dns.hexEncodeName('_ens.foo.test.'),
              now,
              now,
              proof
            );
          }
        });
      dnsregistrarjs = new DNSRegistrar(provider, registrar.address);
      // Stubbing actual dnsprover;
      dnsregistrarjs.dnsprover = dnsprover;

      var claim = await dnsregistrarjs.claim('foo.test');
      assert.equal(claim.numTransactions, dnsProofs + 1);
      await claim.submit({ from: nonOwner });
      assert.equal(await ens.owner(namehash.hash('foo.test')), owner);
    });
  });
});

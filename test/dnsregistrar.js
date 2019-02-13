var ENSRegistry = artifacts.require('./ENSRegistry.sol');
var DummyDNSSEC = artifacts.require('./DummyDNSSEC.sol');
var DNSRegistrarContract = artifacts.require('./DNSRegistrar.sol');
var namehash = require('eth-ens-namehash');
var sha3 = require('js-sha3').keccak_256;

var packet = require('dns-packet');

function hexEncodeName(name){
  return '0x' + packet.name.encode(name).toString('hex');
}

function hexEncodeTXT(keys){
  return '0x' + packet.answer.encode(keys).toString('hex');
}

contract('DNSRegistrar', function(accounts) {
  var registrar = null;
  var ens = null;
  var dnssec = null;
  var dnssecAddress = null;
  var tld = 'test';
  var now = Math.round(new Date().getTime() / 1000);

  beforeEach(async function() {
    ens = await ENSRegistry.new();
    dnssec = await DummyDNSSEC.new();
    registrar = await DNSRegistrarContract.new(
      dnssec.address,
      ens.address
    );
    dnssecAddress = registrar.oracle.call();
    await ens.setSubnodeOwner('0x0', '0x' + sha3(tld), registrar.address);
  });

  it('allows the owner of a DNS name to claim it in ENS', async function() {
    assert.equal(await registrar.oracle(), dnssec.address);
    assert.equal(await registrar.ens(), ens.address);

    var proof = hexEncodeTXT({
      name:'_ens.foo.test',
      type:'TXT',
      class:'IN',
      ttl:3600,
      data:['a=' + accounts[0]]
    });

    var tx = await dnssec.setData(
      16,
      hexEncodeName('_ens.foo.test'),
      now,
      now,
      proof
    );
    assert.equal(parseInt(tx.receipt.status), 1);

    tx = await registrar.claim(hexEncodeName('foo.test'), proof);
    assert.equal(parseInt(tx.receipt.status), 1);

    assert.equal(await ens.owner(namehash.hash('foo.test')), accounts[0]);
  });

  it('allows anyone to zero out an obsolete name', async function() {
    var tx = await dnssec.setData(
      16,
      hexEncodeName('_ens.foo.test'),
      now,
      now,
      ''
    );
    assert.equal(parseInt(tx.receipt.status), 1);

    tx = await registrar.claim(hexEncodeName('foo.test'), '');
    assert.equal(parseInt(tx.receipt.status), 1);

    assert.equal(await ens.owner(namehash.hash('foo.test')), 0);
  });

  it('allows anyone to update a DNSSEC referenced name', async function() {
    var proof = hexEncodeTXT({
      name:'_ens.foo.test',
      type:'TXT',
      class:'IN',
      ttl:3600,
      data:['a=' + accounts[1]]
    });

    var tx = await dnssec.setData(
      16,
      hexEncodeName('_ens.foo.test'),
      now,
      now,
      proof
    );
    assert.equal(parseInt(tx.receipt.status), 1);

    tx = await registrar.claim(hexEncodeName('foo.test'), proof);
    assert.equal(parseInt(tx.receipt.status), 1);
    assert.equal(
      await ens.owner(namehash.hash('foo.test')),
      accounts[1]
    );
  });

  it('does not allow updates with stale records', async function() {
    var proof = hexEncodeTXT({
      name:'_ens.bar.test',
      type:'TXT',
      class:'IN',
      ttl:3600,
      data:['a=' + accounts[0]]
    });

    var tx = await dnssec.setData(
      16,
      hexEncodeName('_ens.foo.test'),
      0,
      0,
      proof
    );
    assert.equal(parseInt(tx.receipt.status), 1);

    tx = undefined;
    try {
      tx = await registrar.claim(hexEncodeName('bar.test'), proof);
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
});

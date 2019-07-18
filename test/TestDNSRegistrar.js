const ENSRegistry = artifacts.require('./ENSRegistry.sol');
const DummyDNSSEC = artifacts.require('./DummyDNSSEC.sol');
const DNSRegistrarContract = artifacts.require('./DNSRegistrar.sol');
const namehash = require('eth-ens-namehash');
const sha3 = require('js-sha3').keccak_256;
const utils = require('./Helpers/Utils');

contract('DNSRegistrar', function(accounts) {
  var registrar = null;
  var ens = null;
  var dnssec = null;
  var tld = 'test';
  var now = Math.round(new Date().getTime() / 1000);

  beforeEach(async function() {
    ens = await ENSRegistry.new();
    dnssec = await DummyDNSSEC.new();
    registrar = await DNSRegistrarContract.new(dnssec.address, ens.address);

    await ens.setSubnodeOwner('0x0', '0x' + sha3(tld), registrar.address);
  });

  it('allows the owner of a DNS name to claim it in ENS', async function() {
    assert.equal(await registrar.oracle(), dnssec.address);
    assert.equal(await registrar.ens(), ens.address);

    var proof = utils.hexEncodeTXT({
      name: '_ens.foo.test',
      type: 'TXT',
      class: 'IN',
      ttl: 3600,
      data: ['a=' + accounts[0]]
    });

    await dnssec.setData(
      16,
      utils.hexEncodeName('_ens.foo.test'),
      now,
      now,
      proof
    );

    await registrar.claim(utils.hexEncodeName('foo.test'), proof);

    assert.equal(await ens.owner(namehash.hash('foo.test')), accounts[0]);
  });

  it('allows anyone to zero out an obsolete name', async function() {
    await dnssec.setData(
      16,
      utils.hexEncodeName('_ens.foo.test'),
      now,
      now,
      '0x'
    );

    await registrar.claim(utils.hexEncodeName('foo.test'), '0x');

    assert.equal(await ens.owner(namehash.hash('foo.test')), 0);
  });

  it('allows anyone to update a DNSSEC referenced name', async function() {
    var proof = utils.hexEncodeTXT({
      name: '_ens.foo.test',
      type: 'TXT',
      class: 'IN',
      ttl: 3600,
      data: ['a=' + accounts[1]]
    });

    await dnssec.setData(
      16,
      utils.hexEncodeName('_ens.foo.test'),
      now,
      now,
      proof
    );

    await registrar.claim(utils.hexEncodeName('foo.test'), proof);
    assert.equal(await ens.owner(namehash.hash('foo.test')), accounts[1]);
  });

  it('does not allow updates with stale records', async function() {
    var proof = utils.hexEncodeTXT({
      name: '_ens.bar.test',
      type: 'TXT',
      class: 'IN',
      ttl: 3600,
      data: ['a=' + accounts[0]]
    });

    await dnssec.setData(16, utils.hexEncodeName('_ens.foo.test'), 0, 0, proof);

    try {
      await registrar.claim(utils.hexEncodeName('bar.test'), proof);
    } catch (error) {
      return utils.ensureException(error);
    }
  });
});

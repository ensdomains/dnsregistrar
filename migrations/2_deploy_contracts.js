const ENSRegistry = artifacts.require("@ensdomains/ens/ENSRegistry");
const DummyDNSSEC = artifacts.require("./DummyDNSSEC");
const DNSRegistrar = artifacts.require("./DNSRegistrar");

const namehash = require('eth-ens-namehash');
const sha3 = require('js-sha3').keccak_256;
const dns = require('../lib/dns.js');
const tld = 'xyz';

module.exports = function(deployer, network) {
    return deployer.then(async () => {

        if (network == "ropsten") {
            await deployer.deploy(
                DNSRegistrar,
                "0xd7296B6044ffD0565062345c2EaA4017024B2D22",
                "0x112234455c3a32fd11230c42e7bccd4a84e02010",
                dns.hexEncodeName(tld + "."),
                namehash.hash(tld)
            );
            return;
        }

        await deployer.deploy([[ENSRegistry], [DummyDNSSEC]]);

        const ens = await ENSRegistry.deployed();
        const dnssec = await DummyDNSSEC.deployed();

        await deployer.deploy(DNSRegistrar, dnssec.address, ens.address);
        const registrar = await DNSRegistrar.deployed();

        await ens.setSubnodeOwner(0, "0x" + sha3(tld), registrar.address);
    });
};

const DNSRegistrar = artifacts.require('./DNSRegistrar');
const TLDPublicSuffixList = artifacts.require('./TLDPublicSuffixList');
require('dotenv').config();

module.exports = function(deployer, network) {
    return deployer.then(async () => {
        if(network == 'test') return;
        await deployer.deploy(TLDPublicSuffixList);
        let psl = await TLDPublicSuffixList.deployed();
        await deployer.deploy(DNSRegistrar, process.env.DNSSEC_ORACLE_ADDRESS, psl.address, process.env.ENS_ADDRESS);
    });
}

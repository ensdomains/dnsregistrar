const DnsProve = require('dnsprovejs');
const dns = require('./dns.js');
const artifact = require("../build/contracts/DNSRegistrar.json");
const Web3 = require('web3');
const abi = artifact.abi;

class DNSRegistrar{
    constructor(provider, oracleAddress, registrarAddress){
        let web3 = new Web3(provider);
        this.registrar = new web3.eth.Contract(abi, registrarAddress)        
        this.dnsprover = new DnsProve(provider);
        this.oracleAddress = oracleAddress;
    }

    async claim(name){
        let proveResult = await this.dnsprover.prove('_ens.' + name, this.oracleAddress);
        return {
            numTransaction: proveResult.unproven + 1,
            owner: proveResult.owner,
            submit: async (params = {})=>{
                await proveResult.submit(params);
                let encodedName = dns.hexEncodeName(name + '.');
                await this.registrar.methods.claim(encodedName, proveResult.lastProof).send(params);
            }
        }
    }
}
module.exports = DNSRegistrar;

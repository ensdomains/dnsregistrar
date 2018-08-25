const DnsProve = require('@ensdomains/dnsprovejs');
const dns = require('./dns.js');
const artifact = require("../build/contracts/DNSRegistrar.json");
const Web3 = require('web3');
const abi = artifact.abi;

class DNSRegistrar{
    constructor(provider, registrarAddress){
        let web3 = new Web3(provider);
        this.registrar = new web3.eth.Contract(abi, registrarAddress)        
        this.dnsprover = new DnsProve(provider);
    }

    async claim(name){
        // for caching purpose.
        if(!this.oracleAddress){
          this.oracleAddress = (await this.registrar.methods.oracle().call()).toLowerCase();
        }
        
        let proveResult = await this.dnsprover.lookup('TXT', '_ens.' + name);
        let oracle = await this.dnsprover.getOracle(this.oracleAddress);
        return {
            oracle:oracle,
            result:proveResult,
            found:proveResult.found,
            getProven: async () => {
                return await oracle.getProven(proveResult)
            },
            getOwner: () => {
                return proveResult.results[proveResult.results.length -1].rrs[0].data[0].toString().split('=')[1];
            },
            submit: async (params = {}) => {
                let data = await oracle.getAllProof(proveResult, params);
                let encodedName = dns.hexEncodeName(name + '.');
                await this.registrar.methods
                    .proveAndClaim(encodedName, data[0], data[1])
                    .send(params)
            }
        }
    }
}
module.exports = DNSRegistrar;

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
        let encodedName = dns.hexEncodeName(name + '.');
        let proveResult = await this.dnsprover.lookup('TXT', '_ens.' + name);
        let oracle = await this.dnsprover.getOracle(this.oracleAddress);
        return {
            oracle:oracle,
            result:proveResult,
            found:proveResult.found,
            nsec:proveResult.nsec,
            getProven: async () => {
                return await oracle.getProven(proveResult)
            },
            getOwner: () => {
                return proveResult.results[proveResult.results.length -1].rrs[0].data[0].toString().split('=')[1];
            },
            submit: async (params = {}) => {
                if(proveResult.nsec){
                    let proofs = proveResult.proofs;
                    await oracle.deleteProof(
                        'TXT', name,
                         proofs[proofs.length -1],
                         proofs[proofs.length -2],
                         params
                    );
                    await this.registrar.methods
                        .claim(encodedName, new Buffer(0))
                        .send(params);
                }else if(proveResult.found){
                    let data = await oracle.getAllProofs(proveResult, params);
                    await this.registrar.methods
                        .proveAndClaim(encodedName, data[0], data[1])
                        .send(params)
                }else{
                    throw("Nothing to prove")
                }
            }
        }
    }
}
module.exports = DNSRegistrar;

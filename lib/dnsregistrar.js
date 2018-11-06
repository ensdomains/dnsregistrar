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
        let textDomain = '_ens.' + name;
        let proveResult = await this.dnsprover.lookup('TXT', textDomain);
        let oracle = await this.dnsprover.getOracle(this.oracleAddress);
        return {
            oracle:oracle,
            result:proveResult,
            found:proveResult.found,
            nsec:proveResult.nsec,
            getProven: async () => {
                return await oracle.getProven(proveResult)
            },
            allProven: async () => {
                return await oracle.allProven(proveResult)
            },
            getOwner: () => {
                return proveResult.results[proveResult.results.length -1].rrs[0].data[0].toString().split('=')[1];
            },
            submit: async (justClaim = false, params = {}) => {
                if(proveResult.nsec){
                    let proofs = proveResult.proofs;
                    console.log('deleteProof', textDomain)
                    let proof = await oracle.knownProof({name:textDomain, type:'TXT'})
                    console.log('proof', proof)
                    await oracle.deleteProof(
                        'TXT', textDomain,
                         proofs[proofs.length -1],
                         proofs[proofs.length -2],
                         params
                    );

                    // Anyone can put empty byte if no record on DNSSEC Oracle
                    proof = '0x'
                    await this.registrar.methods.claim(encodedName, proof).send(params);
                }else if(proveResult.found){
                    let data = await oracle.getAllProofs(proveResult, params);
                    if(justClaim){
                        console.log('claim')
                        await this.registrar.methods
                            .claim(encodedName, data[1])
                            .send(params)
                    }else{
                        console.log('proveAndClaim')
                        await this.registrar.methods
                            .proveAndClaim(encodedName, data[0], data[1])
                            .send(params)
                    }
                }else{
                    throw("Nothing to prove")
                }
            }
        }
    }
}
module.exports = DNSRegistrar;

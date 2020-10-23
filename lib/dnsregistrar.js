const DnsProve = require('@ensdomains/dnsprovejs');
const artifact = require('../build/contracts/DNSRegistrar.json');
const Web3 = require('web3');
const abi = artifact.abi;
var packet = require('dns-packet');

class Claim {
  constructor({ oracle, registrar, result, textDomain, encodedName }) {
    this.oracle = oracle;
    this.registrar = registrar;
    this.result = result;
    this.textDomain = textDomain;
    this.encodedName = encodedName;
  }

  /**
   * returns `Oracle <https://dnsprovejs.readthedocs.io/en/latest/libraries.html#oracle>`_ object
   */
  getOracle() {
    return this.oracle;
  }

  /**
   * returns `DnsResult <https://dnsprovejs.readthedocs.io/en/latest/libraries.html#dnsresult>`_ object
   */
  getResult() {
    return this.result;
  }

  /**
   * returns owner ETH address from the DNS record.
   */
  getOwner() {
    return this.result.results[this.result.results.length - 1].rrs[0].data[0]
      .toString()
      .split('=')[1];
  }

  async getProven() {
    return await this.oracle.getProven(this.result);
  }

  async submitAll(params = {}) {
    await this.oracle.submitAll(this.result, params);
  }

  /**
   * Either submit or delete proof depending on the state of DNSRecord and DNSSEC Oracle
   *
   * - it deletes an entry if DNS record returns NSEC/NSEC3(Next Secure)
   * - it submits proof to DNSSEC Oracle contract if not all proofs are in the contract
   * - it submits proof to DNSSEC Oracle contract and claims via DNSRegistrar contract if not all proofs are in the DNSSEC Oracle contract
   *
   * @param {Object} params - optional parameter to send to smart contract, such as from, gas, etc
   */
  async submit(params = {}) {
    var result = this.result;
    if (result.nsec) {
      let proofs = this.result.proofs;
      await this.oracle.deleteProof(
        'TXT',
        this.textDomain,
        proofs[proofs.length - 1],
        proofs[proofs.length - 2],
        params
      );

      // Anyone can put empty byte if no record on DNSSEC Oracle
      await this.registrar.methods.claim(this.encodedName, '0x').send(params);
    } else if (result.found) {
      let data = await this.oracle.getAllProofs(result, params);
      let allProven = await this.oracle.allProven(result);
      if (allProven) {
        await this.registrar.methods
          .claim(this.encodedName, data[1])
          .send(params);
      } else {
        await this.registrar.methods
          .proveAndClaim(this.encodedName, data[0], data[1])
          .send(params);
      }
    } else {
      throw 'Nothing to prove';
    }
  }
}

class DNSRegistrar {
  constructor(provider, registrarAddress) {
    console.log('***DNSRegistrar1', {provider, registrarAddress, abi})
    let web3 = new Web3(provider);
    console.log('***DNSRegistrar1.1')
    this.registrar = new web3.eth.Contract(abi, registrarAddress);
    console.log('***DNSRegistrar1.2')
    this.dnsprover = new DnsProve(provider);
    console.log('***DNSRegistrar1.3')
  }
  /**
   * returns a claim object which allows you to claim
   * the ownership of a given name on ENS by submitting the proof
   * into DNSSEC oracle as well as claiming the name via the registrar
   * @param {string} name - name of the domain you want to claim
   */
  async claim(name) {
    console.log('*** dnsregistrarjs.claim1')
    // for caching purpose.
    if (!this.oracleAddress) {
      console.log('*** dnsregistrarjs.claim2')
      // debugger
      this.oracleAddress = (await this.registrar.methods
        .oracle()
        .call()).toLowerCase();
    }
    console.log('*** dnsregistrarjs.claim3')
    let encodedName = '0x' + packet.name.encode(name).toString('hex');
    let textDomain = '_ens.' + name;
    let result = await this.dnsprover.lookup('TXT', textDomain);
    console.log('*** dnsregistrarjs.claim4')
    let oracle = await this.dnsprover.getOracle(this.oracleAddress);
    console.log('*** dnsregistrarjs.claim5')
    return new Claim({
      oracle: oracle,
      result: result,
      registrar: this.registrar,
      textDomain: textDomain,
      encodedName: encodedName
    });
  }
}
module.exports = DNSRegistrar;

*******************
Introduction
*******************

In addition to `DNSRegistrar` Truffle based artifact which you can call the smart contract directly, we provide a javascript wrapper which looks up DNS record, extract a proof, submit the proof via DNSSec Oracle, and register to ENS via DNSRegistrar using the proof (or delete if the entry does not exist).

Example

.. code-block:: javascript

        var DNSRegistrarJs = require('@ensdomains/dnsregistrar');
        dnsregistrar = new DNSRegistrarJs(provider, dnsregistraraddress);
        dnsregistrar.claim('foo.test').then((claim)=>{
            claim.submit({from:account});
        })


const leUrl = 'https://acme-v02.api.letsencrypt.org/directory',
      pAcme = require('pico-acme-v2'),
      util  = require('util');
            
// ------------------------------------------------------------------------

// Account
var accD       = false, // Buffer.from(accountKey.d.toString('hex'), 'hex'),
    accX       = false, // Buffer.from(accountKey.x.toString('hex'), 'hex'),
    accY       = false, // Buffer.from(accountKey.y.toString('hex'), 'hex'),
    accountKey = new pAcme.ecdsa(accD, accX, accY);
    
// Domain key    
var exampleD   = false, // Buffer.from(exampleKey.d.toString('hex'), 'hex'),
    exampleX   = false, // Buffer.from(exampleKey.x.toString('hex'), 'hex'),
    exampleY   = false, // Buffer.from(exampleKey.y.toString('hex'), 'hex'),
    exampleKey = new pAcme.ecdsa(exampleD, exampleX, exampleY);
    
// ------------------------------------------------------------------------

// Register new account (or load with private key if exist).
pAcme.registerAccount(accountKey, leUrl)
      .then(function(account) {
        console.log(util.inspect(account, { depth: null }));
        
        // Start/continue/finalize order of domain, just work.
        return pAcme.registerDomains(accountKey, account.location, leUrl, [
          '*.example.com.ar'// Comming soon: , 'example.com.ar'
        ], exampleKey);
      })
      .then(function(certificate) {
        // Get DNS info for challenges, status of order or certificates.
        console.log(util.inspect(certificate, { depth: null }));
      });  

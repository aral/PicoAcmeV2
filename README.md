# Pico Acme V2
Micro tool for ACME V2, wide commented, zero-dependencies and batteries included in only 500 lines of plan javascript.

With an api that makes you fall in love:

## WARNING: This tool is a work in progress, not its ready too, when it is, i remove this warning.
### Last update: 27/09/2018

```Javascript
// ------------------------------------------------------------------------

// Load module and link with ACME provider directory.
const  Acme = require('pico-acme-v2'),
      lAcme = new Acme('https://acme-v02.api.letsencrypt.org/directory'),
      // Optional, my hosting provider API.
      DonWeb = require('donweb');

//-----------------------------------

// For each of your managed accounts...
(function() {
  
  // Load your account, pico acme do all the job for you, only set your webmaster name.
  var account = new lAcme.account(Acme.manager(Acme.ACCOUNT, 'webmaster-name'));

  // When your account is ready, start the job.
  account.on('ready', function(accId /* Your account id */) {

    //-----------------------------------
    
    // For each of your managed certificates in this account...
    (function() {
      
      // Define your domains for the certificate, is an array and accept wildcards.
      // Load your certificate, pico acme do all the job for you, only set your certificate name.
      var domains = [ 'example.com', '*.example.com' ],
          certificate = new lAcme.certificate(account, Acme.manager(Acme.CERTIFICATE, 'example-name'), domains);

      // When the certificate is expired (and also the first time when we need create it)
      certificate.on('expire', function() {
        // Request a new certificate.
        certificate.request();
      });

      // When the certificate request is pending of DNS challenge result
      certificate.on('pending', function(challenge) {
        // Do some task for complete the challenge, for my hosting provider, i build an API for auto complete the challenge.
        // Also, you can do it manually, in this case, only say what the challenge is ready and pico acme will wait.
        DonWeb.addRecord(challenge.domain, challenge.record, 'TXT', challenge.rcvalue, 900, 0)
              .then(function(challengeRecordId) {
                // When add a DNS record, recive an id of it, pico-acme can link it with the certificate.
                Acme.manager.addAttribute(Acme.CERTIFICATE, 'example-name', 'challengeDomainId', challenge.domain);
                Acme.manager.addAttribute(Acme.CERTIFICATE, 'example-name', 'challengeRecordId', challengeRecordId);
                
                // Say what the challenge is ready.
                certificate.challengeReady();
              });
      });

      // When your certificate is ready to rock.
      certificate.on('ready', function(keyPath /* private key path */, pemPath /* certificate pem path */) {
       /** Sample Apache Vhost config:       
       <VirtualHost *:443>
          ServerName example.com
          
          SSLEngine On
          SSLCertificateFile    {pemPath} # <- certificate pem path, never change for the same domains
          SSLCertificateKeyFile {keyPath} # <- certificate key path, never change for the same domains

          SetEnvIf User-Agent ".*MSIE.*" nokeepalive ssl-unclean-shutdown
        </VirtualHost>
        **/
      
        // Do some task after finish the challenge, for my hosting provider, i remove the DNS record.
        var challengeDomainId = Acme.manager.getAttribute(Acme.CERTIFICATE, 'example-name', 'challengeDomainId'),
            challengeRecordId = Acme.manager.getAttribute(Acme.CERTIFICATE, 'example-name', 'challengeRecordId');
        
        DonWeb.removeRecord(challengeDomainId, challengeRecordId)
              .then(function() {
                // After that, i clear the links of the certificate with temp attributes.
                Acme.manager.remAttribute(Acme.DOMAIN, 'example-name', 'challengeDomainId');
                Acme.manager.remAttribute(Acme.DOMAIN, 'example-name', 'challengeRecordId');
              });
      });
      
      // Start to listen certificate changes.
      certificate.watch(true);

    })();
    
    //-----------------------------------
    
  });

  // Start to listen account changes.
  account.watch(true);
  
})();

//-----------------------------------

// ------------------------------------------------------------------------
```

const crypto = require('crypto'),
      dns = require('dns'),
      https = require('https'),
      url = require('url'),
      fs = require('fs');

//-----------------------------------------------------------------------------

function ecdsa(d, x, y) {
  if (!d || !x || !y) {
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.generateKeys();

    d = ecdh.getPrivateKey();
    x = ecdh.getPublicKey().slice(1, 33);
    y = ecdh.getPublicKey().slice(33);
  }

  this.d = d;
  this.x = x;
  this.y = y;
}

ecdsa.prototype.sign = function sign(message, isRaw) {
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(message);
  signer.end();

  if (isRaw) {
    return signer.sign(this.toPEM());
  }

  var signature = signer.sign(this.toPEM()),
      rLength = parseInt(signature.slice(3, 4).toString('hex'), 16),
      r = signature.slice(4, 4 + rLength),
      sLength = parseInt(signature.slice(5 + rLength, 6 + rLength).toString('hex'), 16),
      s = signature.slice(6 + rLength, 6 + rLength + sLength);

  while(r[0] == 0) { r = r.slice(1); }
  while(s[0] == 0) { s = s.slice(1); }

  return Buffer.concat([ r, s ]);
}

ecdsa.prototype.toCSR = function toCSR(domain, isRaw) {
  var domainHex = text2hex(domain),
      segments = Buffer.from('3082' + hexLength(domainHex.length + 488) +
                             '0201003081' + hexLength(domainHex.length + 290) +
                             '310B' +
                             '30090603550406130241523115301306' +
                             '035504080C0C4275656E6F7320416972' +
                             '65733112301006035504070C09436869' +
                             '76696C636F793110300E060355040A0C' +
                             '0743726176696E673111300F06035504' +
                             '0B0C08536F66747761726531' + hexLength(domainHex.length + 18) + 
                             '30' + hexLength(domainHex.length + 14) + '06' +
                             '03550403' +
                             '0C' + hexLength(domainHex.length) + domainHex +
                             '3127302506092A864886F70D' +
                             '01090116187765626D61737465724063' +
                             '726176696E672E636F6D2E6172305930' +
                             '1306072A8648CE3D020106082A8648CE' +
                             '3D03010703420004' +
                             this.x.toString('hex') +
                             this.y.toString('hex') +
                             'A000', 'hex'),
      signature = this.sign(segments, true).toString('hex'),
      content = segments.toString('hex') +
                  '300A06082A8648CE3D04030203' + hexLength(signature.length + 2) + '00' +
                  signature,
      certificate = Buffer.from('3082' + hexLength(content.length) + content, 'hex').toString('base64'),
      csr = '-----BEGIN CERTIFICATE REQUEST-----\n' +
            certificate.match(/.{1,64}/g)
                       .join('\n') + '\n' +
            '-----END CERTIFICATE REQUEST-----';

  if (isRaw) {
    return safe64(certificate);
  }

  return csr;
}

ecdsa.prototype.toThumbprint = function toThumbprint() {
  return safe64(crypto.createHash('sha256').update(JSON.stringify(this.toJWK(true))).digest('base64'));
}

ecdsa.prototype.toJWK = function toJWK(isPublic) {
  var jwk = {
    crv: 'P-256',
    d:   safe64(this.x),
    kty: 'EC',
    x:   safe64(this.x),
    y:   safe64(this.y)
  }

  if (isPublic) {
    delete jwk.d;
  }

  return jwk;
}

ecdsa.prototype.toPEM = function toPEM() {
  return '-----BEGIN EC PRIVATE KEY-----\n' +
         Buffer.from('30770201010420' +
                     this.d.toString('hex') +
                     'A00A06082A8648CE3D030107A144034200' +
                     Buffer.concat([ Buffer.from([0x04]), this.x, this.y ]).toString('hex'), 'hex')
               .toString('base64')
               .match(/.{1,64}/g)
               .join('\n') + '\n' +
         '-----END EC PRIVATE KEY-----';
}

//-----------------------------------------------------------------------------

function doRequest(target, method, headers, body, json) {
  headers['Content-Length'] = body.length;

  return new Promise(function(resolve, reject) {
    var request = https.request(target, { headers: headers, method: method }, function(response) {
      var rawInfo = '';

      response.on('data', function(data) { rawInfo += data; });

      response.on('end', function() {
        if(!json) {
          return resolve({ headers: response.headers, body: rawInfo });
        }

        try {
          rawInfo = JSON.parse(rawInfo);
          resolve({ headers: response.headers, body: rawInfo });
        } catch(e) {
          reject(e);
        }
      });
    });

    request.on('error', reject);
    request.write(body);
    request.end();
  });
}

//-----------------------------------------------------------------------------

function safe64(data) {
  if ( !Buffer.isBuffer(data) ) {
    if (typeof data !== 'string') {
      data = Buffer.from(JSON.stringify(data)).toString('base64');
    }
  } else {
    data = data.toString('base64');
  }

  return data.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function text2hex(txt) {
  for (var n = 0, hex = ''; n < txt.length; n++) {
    hex += ('0' + Number(txt.charCodeAt(n)).toString(16)).slice(-2);
  }
  return hex;
}

function hexLength(length) {
  length = '0' + Number(length / 2).toString(16);
  length = length.slice(-(length.length - length.length % 2));
  return length;
}

// ------------------------------------------------------------------------

function getDirectory(source) {
  return doRequest(source, 'GET', {}, '', true)
          .then(function(result) { return result.body; });
}

function getNonce(source) {
  return doRequest(source, 'GET', {}, '', false)
          .then(function(result) { return result.headers['replay-nonce']; });
}

// ------------------------------------------------------------------------

function registerAccount(accountKey, source) {
  return getDirectory(source)
    .then(function(directory) {
      return getNonce(directory.newNonce)
        .then(function(nonce) {

          var accountJwt = {
                protected: {
                  nonce: nonce,
                  url:   directory.newAccount,
                  alg:   'ES256',
                  jwk:   accountKey.toJWK(true)
                },
                payload: {
                  termsOfServiceAgreed: true,
                  onlyReturnExisting: false,
                  contact: [ 'mailto:john.doe@gmail.com' ]
                }
              },
              headers = {
                'Content-Type': 'application/jose+json'
              }

          accountJwt.protected = safe64(accountJwt.protected);
          accountJwt.payload   = safe64(accountJwt.payload);
          accountJwt.signature = safe64(accountKey.sign(accountJwt.protected + '.' + accountJwt.payload));

          return doRequest(directory.newAccount, 'POST', headers, JSON.stringify(accountJwt), true);
        });
    })
    .then(function(result) {
      return {
        location:   result.headers.location,
        accountId:  result.body.id,
        accountKey: accountKey
      }
    });
}

function registerDomains(accountKey, accountLocation, source, domains, domainKey) {
  return getDirectory(source)
    .then(function(directory) {
      return getNonce(directory.newNonce)
        .then(function(nonce) {
          var orderJwt = {
                protected: {
                  url:   directory.newOrder,
                  nonce: nonce,
                  kid:   accountLocation,
                  alg:   'ES256'
                },
                payload: {
                  identifiers: domains.map(function(domain) { return { value: domain, type: 'dns' } })
                }
              },
              headers = {
                'Content-Type': 'application/jose+json'
              }


          orderJwt.protected = safe64(orderJwt.protected);
          orderJwt.payload   = safe64(orderJwt.payload);
          orderJwt.signature = safe64(accountKey.sign(orderJwt.protected + '.' + orderJwt.payload));

          return doRequest(directory.newOrder, 'POST', headers, JSON.stringify(orderJwt), true);
        })
        .then(function(order) {
          return Promise.all(order.body.authorizations.map(function(authorization) {
            return doRequest(authorization, 'GET', {}, '', true);
          }))
          .then(function(authorizations) {
            return {
              location  : order.headers.location,
              finalize  : order.body.finalize,
              status    : order.body.status,
              challenges: authorizations.map(function(authorization) {
                authorization = authorization.body;
                var challenge = authorization.challenges.filter(function(c) { return c.type === 'dns-01'; }).pop();

                challenge = {
                  domain  : authorization.identifier.value,
                  record  : '_acme-challenge.' + authorization.identifier.value,
                  rcvalue : challenge.token + '.' + accountKey.toThumbprint(),
                  status  : challenge.status,
                  location: challenge.url
                }

                challenge.rcvalue = safe64(crypto.createHash('sha256').update(challenge.rcvalue).digest('base64'));

                return challenge;
              })
            }
          })
          .then(function(order) {
            return Promise.all(order.challenges.map(function(challenge) {
                return new Promise(function(resolve, reject) {
                  dns.resolveTxt(challenge.record, function(err, records) {
                    if (!err && challenge.status === 'pending' && challenge.rcvalue === records[0][0]) {
                      challenge.status = 'challenge-ready';
                    }

                    resolve(challenge);
                  });
                });
              }))
              .then(function(challenges) {
                order.challenges = challenges;
                return order;
              })
          })
          .then(function(order) {
            if(order.challenges.filter(function(challenge) { return challenge.status == 'pending' }).length > 0) {
              return order;
            }

            return Promise.all(order.challenges.map(function(challenge) {
              return new Promise(function(resolve, reject) {
                getNonce(directory.newNonce)
                  .then(function(nonce) {
                    var challengeJwt = {
                          protected: {
                            url:   challenge.location,
                            nonce: nonce,
                            kid:   accountLocation,
                            alg:   'ES256'
                          },
                          payload: {}
                        },
                        headers = {
                          'Content-Type': 'application/jose+json'
                        };

                    challengeJwt.protected = safe64(challengeJwt.protected);
                    challengeJwt.payload   = safe64(challengeJwt.payload);
                    challengeJwt.signature = safe64(accountKey.sign(challengeJwt.protected + '.' + challengeJwt.payload));

                    return doRequest(challenge.location, 'POST', headers, JSON.stringify(challengeJwt), true);
                  })
                  .then(function(status) {
                    function checkStatus(status) {
                      if (status.body.status === 'valid') {
                        challenge.status = 'valid';
                        return resolve(challenge);
                      }

                      setTimeout(function() {
                        doRequest(challenge.location, 'GET', {}, '', true)
                          .then(function(status) {
                            checkStatus(status.body);
                          });
                      }, 5000);
                    }

                    checkStatus(status);
                  });
                });
              }))
              .then(function(challenges) {
                order.challenges = challenges;

                return new Promise(function(resolve, reject) {
                  getNonce(directory.newNonce)
                    .then(function(nonce) {
                      var finalizeJwt = {
                            protected: {
                              url:   order.finalize,
                              nonce: nonce,
                              kid:   accountLocation,
                              alg:   'ES256'
                            },
                            payload: {
                              csr: domainKey.toCSR(domains.join(','), true)
                            }
                          },
                          headers = {
                            'Content-Type': 'application/jose+json'
                          };
                          
                      finalizeJwt.protected = safe64(finalizeJwt.protected);
                      finalizeJwt.payload   = safe64(finalizeJwt.payload);
                      finalizeJwt.signature = safe64(accountKey.sign(finalizeJwt.protected + '.' + finalizeJwt.payload));

                      return doRequest(order.finalize, 'POST', headers, JSON.stringify(finalizeJwt), true);
                    })
                    .then(function(status) {
                      function checkStatus(status) {
                        if (status.status === 'valid') {
                          order.status = 'valid';
                          order.certificate = status.certificate;
                          return resolve(order);
                        }

                        setTimeout(function() {
                          doRequest(order.location, 'GET', {}, '', true)
                            .then(function(status) {
                              checkStatus(status.body);
                            });
                        }, 5000);
                      }

                      checkStatus(status.body);
                    });

                })
              })
              .then(function(order) {
                return doRequest(order.certificate, 'GET', {}, '', false);
              })
              .then(function(certificate) {
                var file = safe64(Buffer.from(domains.join('-'))) + '.certs';
                fs.writeFileSync(safe64(Buffer.from(domains.join('-'))) + '.certs', certificate.body);
                
                return {
                  certificate: file
                };
              });
          });
        });
    })
    .then(function(result) {
      return result;
    });
}

//-----------------------------------------------------------------------------

module.exports = {
  registerAccount: registerAccount,
  registerDomains: registerDomains,
  ecdsa: ecdsa
}

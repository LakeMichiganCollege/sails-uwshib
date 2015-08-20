'use strict';

/**
 * UW Shibboleth Authentication Module for sails-auth
 *
 * This module exposes a sails-auth compatible passport Strategy object that is pre-configured to work with the UW's Shibboleth
 * Identity Provider (IdP). To use this, you must register your server with the UW IdP.
 *
 * This modules is based on passport-uwshib by Dave Stearns. https://github.com/drstearns/passport-uwshib
 *
 * For details about sails-uwshib, see https://github.com/kevintechie/sails-uwshib
 *
 * @module sails-uwshib
 * @author Kevin Coleman
 */

var saml = require('passport-saml');
var util = require('util');

var uwIdPCert = 'MIID/TCCAuWgAwIBAgIJAMoYJbDt9lKKMA0GCSqGSIb3DQEBBQUAMFwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJXQTEhMB8GA1UEChMYVW5pdmVyc2l0eSBvZiBXYXNoaW5ndG9uMR0wGwYDVQQDExRpZHAudS53YXNoaW5ndG9uLmVkdTAeFw0xMTA0MjYxOTEwMzlaFw0yMTA0MjMxOTEwMzlaMFwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJXQTEhMB8GA1UEChMYVW5pdmVyc2l0eSBvZiBXYXNoaW5ndG9uMR0wGwYDVQQDExRpZHAudS53YXNoaW5ndG9uLmVkdTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMH9G8m68L0Hf9bmf4/7c+ERxgDQrbq50NfSi2YTQWc1veUIPYbZy1agSNuc4dwn3RtC0uOQbdNTYUAiVTcYgaYceJVB7syWf9QyGIrglZPMu98c5hWb7vqwvs6d3s2Sm7tBib2v6xQDDiZ4KJxpdAvsoPQlmGdgpFfmAsiYrnYFXLTHgbgCc/YhV8lubTakUdI3bMYWfh9dkj+DVGUmt2gLtQUzbuH8EU44vnXgrQYSXNQkmRcyoE3rj4Rhhbu/p5D3P+nuOukLYFOLRaNeiiGyTu3P7gtc/dy/UjUrf+pH75UUU7Lb369dGEfZwvVtITXsdyp0pBfun4CP808H9N0CAwEAAaOBwTCBvjAdBgNVHQ4EFgQUP5smx3ZYKODMkDglkTbduvLcGYAwgY4GA1UdIwSBhjCBg4AUP5smx3ZYKODMkDglkTbduvLcGYChYKReMFwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJXQTEhMB8GA1UEChMYVW5pdmVyc2l0eSBvZiBXYXNoaW5ndG9uMR0wGwYDVQQDExRpZHAudS53YXNoaW5ndG9uLmVkdYIJAMoYJbDt9lKKMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAEo7c2CNHEI+Fvz5DhwumU+WHXqwSOK47MxXwNJVpFQ9GPR2ZGDAq6hzLJLAVWcY4kB3ECDkRtysAWSFHm1roOU7xsU9f0C17QokoXfLNC0d7KoivPM6ctl8aRftU5moyFJkkJX3qSExXrl053uxTOQVPms4ypkYv1A/FBZWgSC8eNoYnBnv1Mhy4m8bfeEN7qT9rFoxh4cVjMH1Ykq7JWyFXLEB4ifzH4KHyplt5Ryv61eh6J1YPFa2RurVTyGpHJZeOLUIBvJu15GzcexuDDXe0kg7sHD6PbK0xzEF/QeXP/hXzMxR9kQXB/IR/b2k4ien+EM3eY/ueBcTZ95dgVM=';
var uwIdPEntryPoint = 'https://idp.u.washington.edu/idp/profile/SAML2/Redirect/SSO';
var strategyName = 'uwsaml';

// map of possible profile attributes and what name
// map of possible profile attributes and what name
// we should give them on the resulting user object
// add to this with other attrs if you request them
var profileAttrs = {
  'urn:oid:0.9.2342.19200300.100.1.1': 'netId',
  'urn:oid:2.16.840.1.113730.3.1.241': 'displayName',
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.1':  'affiliation',
  'urn:oid:2.5.4.3':                   'cn',
  'urn:oid:0.9.2342.19200300.100.1.3': 'email',
  'urn:oid:2.16.840.1.113730.3.1.3':   'empNum',
  'urn:oid:1.3.6.1.4.1.5923.1.1.1.6':  'principalName',
  'urn:oid:2.5.4.42':                  'givenName',
  'urn:oid:2.5.4.18':                  'box',
  'urn:oid:2.5.4.20':                  'phone',
  'urn:oid:2.5.4.4':                   'surname',
  'urn:oid:2.5.4.12':                  'title',
  'urn:oid:1.2.840.113994.200.21':     'studentId',
  'urn:oid:1.2.840.113994.200.24':     'regId'
};

module.exports.convertProfileToUser = function (profile) {
  var user = {};
  var niceName;
  var idx;
  var keys = Object.keys(profile);
  var key;

  for (idx = 0; idx < keys.length; ++idx) {
    key = keys[ idx ];
    niceName = profileAttrs[ key ];
    if (niceName) {
      user[ niceName ] = profile[ key ];
    }
  }

  user.provider = strategyName;
  user.id = user.netId;
  user.emails = [
    {
      value: user.principalName
    }
  ];
  console.log('returning user', user);
  return user;
};

/**
 * Passport Strategy for UW Shibboleth Authentication
 *
 * This class extends passport-saml.Strategy, providing the necessary options for the UW Shibboleth IdP
 * and converting the returned profile into a user object with sensible property names.
 *
 * @param {Object} options - Configuration options
 * @param {string} options.entityId - Your server's entity id (often same as domain name)
 * @param {string} options.domain - Your server's domain name
 * @param {string} options.callbackUrl - Relative URL for the login callback (we will add https:// and domain)
 * @param {string} options.privateKey - Optional private key for signing SAML requests
 * @param verifyUser - The callback used to verify that the user is registered in your application database
 * @constructor
 */
module.exports.Strategy = function (options, verifyUser) {
  options = options || {};
  options.entryPoint = options.entryPoint || uwIdPEntryPoint;
  options.cert = options.cert || uwIdPCert;
  options.identifierFormat = null;
  options.issuer = options.issuer || options.entityId || options.domain;
  options.callbackUrl = 'https://' + options.domain + options.callbackUrl;
  options.decryptionPvk = options.privateKey;
  options.privateCert = options.privateKey;

  saml.Strategy.call(this, options, verifyUser);
  this.name = strategyName;
};

util.inherits(module.exports.Strategy, saml.Strategy);

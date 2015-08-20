Sails-UWShib
===============

This package implements a Passportjs authentication strategy that works with the University of Washington's Shibboleth single-sign on service. This package uses the [passport-saml](https://github.com/bergie/passport-saml) package for all the heavy lifting, but sets all the default options so that it works properly with the UW Shibboleth Identity Provider (IdP).

This strategy is based on the [Passport-UWShib](https://github.com/drstearns/passport-uwshib) package created by David Stearns and was modified to support the passport authentication integration pattern used by [sails-auth](https://github.com/tjwebb/sails-auth). Please see the GitHub repositories for the passport-uwshib and sails-auth packages for implementation details.

Installation
------------
Simply use NPM to install the package as a project dependency.

    npm install sails-uwshib --save

Configuration
-------------
While this strategy will work with any Passportjs-based authentication implementation, these configuration instructions are specific to sails-auth.

**< project >/config/passport.js**
Setup the passport configuration object.

    passport: {
      uwsaml: {
        name:     'UW Shibboleth',
        protocol: 'uwsaml',
        strategy: require('sails-uwshib').Strategy,
        options:  {
          entityId:    'https://' + domain,
          privateKey:  privateKey,
          callbackUrl: '/auth/uwsaml/callback',
          domain:      domain
        }
      }
    }

The `domain` and `privateKey` variables need to be set before the configuration object is created. These variables can be read from environment variables and / or the file system.

The callbackUrl follows the pattern established by sails-auth and should not be changed.

**< project >/config/routes/sails-auth.js**
The default sails-auth installation defines a route for the authentication callback. However, the dependent passport-saml module requires a POST http method rather hand a GET, so you'll have to create a new route and point it at the AuthController.callback method.

    routes: {
      'post /auth/:provider/callback': 'AuthController.callback'

**< project >/services/protocols/uwsaml.js**
Create the sails-auth Passport protocol adapter file.

    'use strict';
    var uwshib = require('sails-uwshib');
    module.exports = function (req, profile, next) {
      profile = uwshib.convertProfileToUser(profile);
      var query = {
        identifier: profile.netId,
        protocol:   'uwsaml'
      };
    
      sails.services.passport.connect(req, query, profile, next);
    };

**< project >/services/protocols/index.js**
Require the uwsaml.js protocol file. 

    uwsaml: require('./uwsaml')

**< project >/services/protocols/passport.js**
There is currently a bug in sails-auth (as of version v1.3.1) that prevents local project protocol files from being loaded. Add the following line to work around the bug.

    protocols: require('./protocols')

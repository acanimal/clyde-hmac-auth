"use strict";

var Hmmac = require("hmmac");


/**
 * Simple plain HMAC authentication implementation based on hmmac package.
 *
 * @public
 * @param  {String} name Name of the filter
 * @param  {Object} config JavaScript object with filter configuration
 * @returns {Function} Middleware function implementing the filter.
 */
module.exports.init = function(name, config) {

  // Make config to be at least an empty object
  config = config || {};

  // NOTE: Workaround to run hmmac-middleware so it has access to the request
  // object in credentialProvider function.
  // See: https://github.com/cmawhorter/hmmac/issues/13
  return function(req, res, next) {

    // Hmmac options
    var options = {
      algorithm: "sha256",
      acceptableDateSkew: 900, // in seconds, def 15 minutes. only done if date is signed
      credentialProvider: function(key, callback) { // Provider function to get secret value from a given key value.
        var secret = (config.consumers) ? config.consumers[key] : null;
        if (!secret) {
          return callback(null);
        }
        // Store user information within the request
        req.user = {
          userId: key
        };
        return callback({key: key, secret: secret});
      },
      credentialProviderTimeout: 1, // in seconds. time to wait for credentialProvider to return
      signatureEncoding: "hex", // signature encoding. valid = binary, hex or base64
      signedHeaders: [ "host", "content-type", "date" ],
      wwwAuthenticateRealm: config.realm || "clyde",
      scheme: Hmmac.schemes.load("plain")
    };

    // Custom responder function.
    function customResponder(valid) {
      if (valid === true) {
        // If user is valid continue middleware chain (the user object has been
        // added on the credentialProvider function)
        return next();
      } else {
        // If user is not valid remove user information from request and return error.
        delete req.user;
        res.statusCode = 401;
        if (options.wwwAuthenticateRealm) {
          res.setHeader("WWW-Authenticate", options.scheme.getServiceLabel()
            + " realm=\"" + options.wwwAuthenticateRealm.replace(/"/g, "'") + "\"");
        }
        var err = new Error("Unauthorized");
        err.statusCode = 401;
        return next(err);
      }
    }

    // Run hmmac-middleware passing current req, res and next references
    Hmmac.middleware(options, customResponder).apply(this, [req, res, next]);
  };
};

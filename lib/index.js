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

  // Provider function to get secret value from a given key value.
  function credentialProvider(key, callback) {
    var secret = (config.consumers) ? config.consumers[key] : null;
    if (!secret) {
      return callback(null);
    }
    return callback({key: key, secret: secret});
  }

  // Hmmac options
  var options = {
    algorithm: "sha256",
    acceptableDateSkew: 900, // in seconds, def 15 minutes. only done if date is signed
    credentialProvider: credentialProvider,
    credentialProviderTimeout: 1, // in seconds. time to wait for credentialProvider to return
    signatureEncoding: "hex", // signature encoding. valid = binary, hex or base64
    signedHeaders: [ "host", "content-type", "date" ],
    wwwAuthenticateRealm: config.realm || "clyde",
    scheme: Hmmac.schemes.load("plain")
  };
  // Create hmmac instance
  var hmmac = new Hmmac(options);

  // Custom responder function.
  function customResponder(valid, req, res, next) {
    if (valid === true) {
      // Authentication filters requires to attach a user object to the request.
      req.user = {
        userId: "" // TODO - Get key reference
      };
      return next();
    } else {
      res.statusCode = 401;
      if (hmmac.config.wwwAuthenticateRealm) {
        res.setHeader("WWW-Authenticate", hmmac.config.scheme.getServiceLabel.call(hmmac)
          + " realm=\"" + hmmac.config.wwwAuthenticateRealm.replace(/"/g, "'") + "\"");
      }
      var err = new Error("Unauthorized");
      err.statusCode = 401;
      return next(err);
    }
  }

  // Return hmmac middleware
  return Hmmac.middleware(hmmac, customResponder);
};

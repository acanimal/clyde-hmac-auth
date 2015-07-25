"use strict";

var path = require("path"),
    expect = require("chai").expect,
    http = require("http"),
    Hmmac = require("hmmac"),
    clyde = require("clyde");


describe("hmac-auth", function() {

  var server,
      port = 8888,
      hmmac = new Hmmac({ scheme: Hmmac.schemes.load("plain") });

  before(function(done) {
    var logDirectory = path.join(__dirname, "../tmp");
    var options = {
      logfile: path.join(logDirectory, "clyde.log"),
      loglevel: "info",

      prefilters: [
        {
          id: "hmac-auth",
          path: path.join(__dirname, "../lib/index.js"),
          config: {
            realm: "test",
            consumers: {
              keyA: "secretA"
            }
          }
        }
      ],

      providers: [
        {
          id: "provider",
          context: "/provider",
          target: "http://server"
        }
      ]
    };

    // Start clyde server with test configuration
    // Create server with clyde's middleware options
    var middleware = clyde.createMiddleware(options);
    server = http.createServer(middleware);
    server.listen(port);
    server.on("listening", function() {
      done();
    });
  });

  after(function() {
    // Stop clyde server
    server.close();
  });


  it("should match the authentication realm", function(done) {
    var body = "request body";
    var httpRequest = {
      host: "localhost",
      port: port,
      path: "/foo",
      method: "GET",
      headers: {
        "x-auth-signedheaders": "host; content-type; date",
        "Content-Type": "text/plain",
        "Date": new Date().toUTCString()
      }
    };

    // Sign request with invalid secret
    hmmac.sign(httpRequest, {key: "keyA", secret: "bad-secret"});

    // Make request
    var req = http.request(httpRequest, function(res) {
      expect(res.headers["www-authenticate"]).contains("realm=\"test\"");
      expect(res.statusCode).to.be.equal(401);
      done();
    });
    req.end(body);
  });


  it("should fail due invalid authentication", function(done) {
    var body = "request body";
    var httpRequest = {
      host: "localhost",
      port: port,
      path: "/foo",
      method: "GET",
      headers: {
        "x-auth-signedheaders": "host; content-type; date",
        "Content-Type": "text/plain",
        "Date": new Date().toUTCString()
      }
    };

    // Sign request with invalid secret
    hmmac.sign(httpRequest, {key: "keyA", secret: "bad-secret"});

    // Make request
    var req = http.request(httpRequest, function(res) {
      expect(res.statusCode).to.be.equal(401);
      done();
    });
    req.end(body);
  });


  it("should success HMAC authentication", function(done) {
    var body = "request body";
    var httpRequest = {
      host: "localhost",
      port: port,
      path: "/foo",
      method: "GET",
      headers: {
        "x-auth-signedheaders": "host; content-type; date",
        "Content-Type": "text/plain",
        "Date": new Date().toUTCString()
      }
    };

    // Sign request with invalid secret
    hmmac.sign(httpRequest, {key: "keyA", secret: "secretA"});

    // Make request
    var req = http.request(httpRequest, function(res) {
      // Note we are requesting an invalid resource so we must get a 404
      expect(res.statusCode).to.be.equal(404);
      done();
    });
    req.end(body);
  });

});

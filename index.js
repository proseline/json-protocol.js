var AJV = require("ajv");
var Duplexify = require("duplexify");
var assert = require("assert");
var inherits = require("inherits");
var lengthPrefixedStream = require("length-prefixed-stream");
var sodium = require("sodium-universal");
var through2 = require("through2");

var STREAM_NONCEBYTES = sodium.crypto_stream_NONCEBYTES;
var STREAM_KEYBYTES = sodium.crypto_stream_KEYBYTES;

var HANDSHAKE_PREFIX = 0;

module.exports = function(options) {
  assert.equal(typeof options, "object", "argument must be Object");

  var version = options.version;
  assert.equal(typeof version, "number", "version must be Number");
  assert(version > 0, "version must be greater than zero");
  assert(Number.isSafeInteger(version), "version must be safe integer");

  var messages = options.messages;
  assert.equal(typeof messages, "object", "messages must be Object");
  var messageNames = Object.keys(messages);
  assert(messageNames.length !== 0, "messages must have properties");

  var ajv = new AJV();
  var types = {};
  var typesByPrefix = {};
  var prefixes = [0];
  messageNames.sort().forEach(function(name, index) {
    var options = messages[name];
    assert(options.hasOwnProperty("schema"), "message type must have schema");
    var schema = options.schema;
    var valid = ajv.compile(schema);
    var prefix = index + 1; // Reserve prefix 0 for handshakes.
    prefixes.push(prefix);
    types[name] = typesByPrefix[prefix] = {
      name: name,
      schema: schema,
      valid: valid,
      prefix: prefix
    };
    Protocol.prototype[name] = function(data, callback) {
      this._sendMessage(name, data, callback);
    };
  });
  var validMessage = ajv.compile({
    type: "array",
    items: [
      { type: "number", enum: prefixes },
      {
        /* anything */
      }
    ],
    additionalItems: false
  });
  var validHandshake = ajv.compile({
    type: "object",
    properties: {
      version: { type: "number", multipleOf: 1, minimum: 1 },
      nonce: { type: "string", pattern: "^[a-f0-9]{48}$" }
    },
    required: ["version", "nonce"],
    additionalProperties: false
  });

  function Protocol(options) {
    if (!(this instanceof Protocol)) return new Protocol(options);
    assert.equal(typeof options, "object", "argument must be object");
    var self = this;
    var replicationKey = (self._replicationKey = options.replicationKey);
    assert(Buffer.isBuffer(replicationKey), "replicationKey must be Buffer");
    assert.equal(
      replicationKey.byteLength,
      STREAM_KEYBYTES,
      "replicationKey must be crypto_stream_KEYBYTES long"
    );

    self._initializeReadable();
    self._initializeWritable();
    Duplexify.call(self, self._writableStream, self._readableStream);
  }

  Protocol.prototype._initializeReadable = function() {
    var self = this;
    // Cryptographic stream using our nonce and the secret key.
    self._sendingNonce = Buffer.alloc(STREAM_NONCEBYTES);
    sodium.randombytes_buf(self._sendingNonce);
    self._sendingCipher = initializeCipher(
      self._sendingNonce,
      self._replicationKey
    );
    self._encoderStream = lengthPrefixedStream.encode();
    self._readableStream = through2.obj(function(chunk, _, done) {
      assert(Buffer.isBuffer(chunk));
      // Once we've sent our nonce, encrypt.
      if (self._sentNonce) {
        self._sendingCipher.update(chunk, chunk);
      }
      this.push(chunk);
      done();
    });
    self._encoderStream
      .pipe(self._readableStream)
      .once("error", function(error) {
        self.destroy(error);
      });
  };

  Protocol.prototype._initializeWritable = function() {
    var self = this;
    // Cryptographic stream using our peer's nonce, which we've yet
    // to receive, and the secret key.
    self._receivingNonce = null;
    self._receivingCipher = null;
    self._writableStream = through2(function(chunk, encoding, done) {
      assert(Buffer.isBuffer(chunk));
      // Once we've been given a nonce, decrypt.
      if (self._receivingCipher) {
        self._receivingCipher.update(chunk, chunk);
      }
      // Until we've been given a nonce, write in the clear.
      done(null, chunk);
    });
    self._parserStream = through2.obj(function(chunk, _, done) {
      self._parse(chunk, function(error) {
        if (error) return done(error);
        done();
      });
    });
    self._writableStream
      .pipe(lengthPrefixedStream.decode())
      .pipe(self._parserStream)
      .once("error", function(error) {
        self.destroy(error);
      });
  };

  Protocol.prototype.handshake = function(callback) {
    assert.equal(typeof callback, "function");
    var self = this;
    if (self._sentNonce) return callback(new Error("already sent handshake"));
    self._encode(
      HANDSHAKE_PREFIX,
      {
        version: version,
        nonce: self._sendingNonce.toString("hex")
      },
      function(error) {
        if (error) return callback(error);
        self._sentNonce = true;
        callback();
      }
    );
  };

  Protocol.prototype._sendMessage = function(typeName, data, callback) {
    assert(types.hasOwnProperty(typeName));
    assert.equal(typeof callback, "function");
    var type = types[typeName];
    assert(type.valid(data));
    this._encode(type.prefix, data, callback);
  };

  Protocol.prototype.finalize = function(callback) {
    assert(typeof callback === "function");
    var self = this;
    self._finalize(function(error) {
      if (error) return self.destroy(error);
      self._encoderStream.end(callback);
      self._sendingCipher.final();
      self._sendingCipher = null;
      self._receivingCipher.final();
      self._receivingCipher = null;
    });
  };

  Protocol.prototype._encode = function(prefix, data, callback) {
    var buffer = Buffer.from(JSON.stringify([prefix, data]), "utf8");
    this._encoderStream.write(buffer, callback);
  };

  Protocol.prototype._parse = function(message, callback) {
    try {
      var parsed = JSON.parse(message);
    } catch (error) {
      return callback(error);
    }
    if (!validMessage(parsed)) {
      return callback(new Error("invalid message"));
    }
    var prefix = parsed[0];
    var body = parsed[1];
    if (prefix === 0 && validHandshake(body)) {
      if (!this._receivingCipher) {
        this._receivingNonce = Buffer.from(body.nonce, "hex");
        assert.equal(this._receivingNonce.byteLength, STREAM_NONCEBYTES);
        this._receivingCipher = initializeCipher(
          this._receivingNonce,
          this._replicationKey
        );
        this.emit("handshake");
        return callback();
      }
      this.emit("handshake");
      return callback();
    }
    var type = typesByPrefix[prefix];
    if (!type || !type.valid(body)) {
      this.emit("invalid", body);
      return callback();
    }
    this.emit(type.name, body);
    return callback();
  };

  inherits(Protocol, Duplexify);

  return Protocol;
};

function initializeCipher(nonce, secretKey) {
  assert(Buffer.isBuffer(nonce));
  assert.equal(nonce.byteLength, STREAM_NONCEBYTES);
  assert(Buffer.isBuffer(secretKey));
  assert.equal(secretKey.byteLength, STREAM_KEYBYTES);
  return sodium.crypto_stream_xor_instance(nonce, secretKey);
}

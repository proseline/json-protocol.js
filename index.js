var AJV = require('ajv')
var Duplexify = require('duplexify')
var assert = require('nanoassert')
var inherits = require('inherits')
var lengthPrefixedStream = require('length-prefixed-stream')
var sodium = require('sodium-universal')
var strictSchema = require('strict-json-object-schema')
var stableStringify = require('fast-json-stable-stringify')
var through2 = require('through2')

var STREAM_NONCEBYTES = sodium.crypto_stream_NONCEBYTES
var STREAM_KEYBYTES = sodium.crypto_stream_KEYBYTES

var SIGN_BYTES = sodium.crypto_sign_BYTES
var SEEDBYTES = sodium.crypto_sign_SEEDBYTES
var PUBLICKEYBYTES = sodium.crypto_sign_PUBLICKEYBYTES
var SECRETKEYBYTES = sodium.crypto_sign_SECRETKEYBYTES

var HANDSHAKE_PREFIX = 0

// Implementation Overview
//
// json-protocol builds duplex streams that read and write
// JSON-encoded messages. Each message across the wire is
// encoded as an array. The first element is a positive
// integer Number prefix indicating the type of the message
// data payload. The last element is the JSON-encoded
// message data payload.
//
// When cryptographic signing is enabled for the protocol,
// tuples contain a second element: a hex-encoded Ed25519
// signature of the stringified message data payload. We use
// a "stable" JSON stringifier that sorts object properties
// by key, so that equal JSON structures stringify the same,
// and peers can reliably verify signatures.
//
// Each protocol reserves prefix `0` for handshake messages.
// Handshakes exchange at least protocol versions. Protocol
// version mismatches produce errors.
//
// When the protocol is encrypted, handshake messages also
// exchange random stream cipher nonces. Having sent a
// stream-cipher nonce, each peer sends all subsequent
// messages enciphered with the nonce and a key shared
// out-of-band.

module.exports = function (options) {
  assert(
    typeof options === 'object',
    'argument must be Object'
  )

  // Set flags for optional encryption features.
  var encrypt = options.encrypt
  var sign = options.sign
  var requireSigningKeys = options.requireSigningKeys

  var version = options.version
  assert(
    typeof version === 'number',
    'version must be Number'
  )
  assert(version > 0, 'version must be greater than zero')
  assert(
    Number.isSafeInteger(version),
    'version must be safe integer'
  )

  // Turn message specification into message types and compile schemas.
  var messages = options.messages
  assert(
    typeof messages === 'object',
    'messages must be Object'
  )
  var messageNames = Object.keys(messages)
  assert(messageNames.length !== 0, 'messages must have properties')
  var ajv = new AJV()
  // Map message types from name so we can access them from methods.
  var messageTypesByName = {}
  // Map message types from prefix so we can validate them quickly.
  var messageTypesByPrefix = {}
  // List prefixes for use in our schema for tuples.
  var messageTypePrefixes = [HANDSHAKE_PREFIX]
  messageNames.sort().forEach(function (name, index) {
    var options = messages[name]
    assert(
      options.hasOwnProperty('schema'),
      'message type must have schema'
    )
    if (options.hasOwnProperty('verify')) {
      assert(
        typeof options.verify === 'function',
        'verify must be Function'
      )
    }
    var schema = options.schema
    var validate = ajv.compile(schema)
    var prefix = index + 1 // Reserve prefix 0 for handshakes.
    messageTypePrefixes.push(prefix)
    messageTypesByName[name] = messageTypesByPrefix[prefix] = {
      name: name,
      validate: validate,
      verify: options.verify || returnTrue,
      prefix: prefix
    }
  })

  // Build a validation predicate for message tuples using a
  // JSON Schema.
  var tupleItems = [
    {
      title: 'Message Type Prefix',
      type: 'number',
      enum: messageTypePrefixes
    }
  ]
  if (sign) {
    tupleItems.push({
      title: 'Signature',
      type: 'string',
      pattern: '^[a-f0-9]{128}$'
    })
  }
  tupleItems.push({ title: 'Message Payload' })
  var validTuple = ajv.compile({
    title: 'Protocol Message',
    type: 'array',
    items: tupleItems,
    additionalItems: false
  })

  // Build a validation predicate for handshake message
  // bodies using a JSON Schema.
  var handshakeProperties = {
    version: {
      title: 'Protocol Version',
      type: 'number',
      multipleOf: 1,
      minimum: 1
    }
  }
  if (encrypt) {
    handshakeProperties.nonce = {
      title: 'Encryption Nonce',
      type: 'string',
      pattern: '^[a-f0-9]{' + STREAM_NONCEBYTES * 2 + '}$'
    }
  }
  var validHandshake = ajv.compile(strictSchema(handshakeProperties))

  // Prototype for duplex streams to return to the caller.
  function Protocol (options) {
    if (encrypt || sign || requireSigningKeys) {
      assert(
        typeof options === 'object',
        'argument must be object'
      )
    }

    if (!(this instanceof Protocol)) return new Protocol(options)

    // Require encryption key for encrypted protocols.
    if (encrypt) {
      assert(
        Buffer.isBuffer(options.encryptionKey),
        'encryptionKey must be Buffer'
      )
      assert(
        options.encryptionKey.byteLength === STREAM_KEYBYTES,
        'encryptionKey must be crypto_stream_KEYBYTES long'
      )
      this._encryptionKey = options.encryptionKey
    }

    // Require a key pair or seed for signed protocols.
    if (sign || requireSigningKeys) {
      if (
        options.hasOwnProperty('publicKey') &&
        options.hasOwnProperty('secretKey')
      ) {
        assert(
          Buffer.isBuffer(options.publicKey),
          'publicKey must be Buffer'
        )
        assert(
          options.publicKey.byteLength === PUBLICKEYBYTES,
          'seed must be crypto_sign_PUBLICKEYBYTES long'
        )
        assert(
          Buffer.isBuffer(options.secretKey),
          'secretKey must be Buffer'
        )
        assert(
          options.secretKey.byteLength === SECRETKEYBYTES,
          'seed must be crypto_sign_SECRETKEYBYTES long'
        )
        this.publicKey = options.publicKey
        this.secretKey = options.secretKey
      } else if (options.hasOwnProperty('seed')) {
        assert(Buffer.isBuffer(options.seed), 'seed must be Buffer')
        assert(
          options.seed.byteLength === SEEDBYTES,
          'seed must be crypto_sign_SEEDBYTES long'
        )
        var seed = options.seed
        this.publicKey = Buffer.alloc(PUBLICKEYBYTES)
        this.secretKey = Buffer.alloc(SECRETKEYBYTES)
        sodium.crypto_sign_seed_keypair(
          this.publicKey,
          this.secretKey,
          seed
        )
      } else {
        assert(false, 'must provide secretKey and publicKey or seed')
      }
    }

    this._initializeReadable()
    this._initializeWritable()
    Duplexify.call(this, this._writableStream, this._readableStream)
  }

  inherits(Protocol, Duplexify)

  messageNames.forEach(function (name) {
    Protocol.prototype[name] = function (data, callback) {
      this._sendMessage(name, data, callback)
    }
  })

  // Initialize the readable half of the duplex stream, for
  // sending messages to our peer.
  Protocol.prototype._initializeReadable = function () {
    var self = this

    if (encrypt) {
      // Cryptographic stream using our nonce and the
      // shared encryption key.
      self._sendingNonce = Buffer.alloc(STREAM_NONCEBYTES)
      sodium.randombytes_buf(self._sendingNonce)
      self._sendingCipher = initializeCipher(
        self._sendingNonce,
        self._encryptionKey
      )
    }

    self._encoderStream = lengthPrefixedStream.encode()

    self._readableStream = through2.obj(function (chunk, _, done) {
      assert(Buffer.isBuffer(chunk))
      // Once we've sent our nonce, encrypt.
      if (encrypt && self._sentHandshake) {
        self._sendingCipher.update(chunk, chunk)
      }
      // Until we send a nonce, write in the clear.
      done(null, chunk)
    })

    self._encoderStream
      .pipe(self._readableStream)
      .once('error', function (error) {
        self.destroy(error)
      })
  }

  // Initialize the readable half of the duplex stream, for
  // receiving messages from our peer.
  Protocol.prototype._initializeWritable = function () {
    var self = this

    if (encrypt) {
      // Cryptographic stream using our peer's nonce, which we've yet
      // to receive, and the shared encryption key.
      self._receivingNonce = null
      self._receivingCipher = null
    }

    self._writableStream = through2(function (chunk, encoding, done) {
      assert(Buffer.isBuffer(chunk))
      // Once we've been given a nonce, decrypt.
      if (encrypt && self._receivingCipher) {
        self._receivingCipher.update(chunk, chunk)
      }
      // Until we've been given a nonce, write in the clear.
      done(null, chunk)
    })

    self._parserStream = through2.obj(function (chunk, _, done) {
      self._parse(chunk, function (error) {
        if (error) return done(error)
        done()
      })
    })

    self._writableStream
      .pipe(lengthPrefixedStream.decode())
      .pipe(self._parserStream)
      .once('error', function (error) {
        self.destroy(error)
      })
  }

  // Send our handshake message.
  Protocol.prototype.handshake = function (callback) {
    assert(typeof callback === 'function')
    var self = this
    if (self._sentHandshake) { return callback(new Error('already sent handshake')) }
    var body = { version: version }
    if (encrypt) body.nonce = self._sendingNonce.toString('hex')
    self._encode(HANDSHAKE_PREFIX, body, function (error) {
      /* istanbul ignore if */
      if (error) return callback(error)
      self._sentHandshake = true
      callback()
    })
  }

  // Send a protocol-defined message.
  //
  // The constructor adds functions to the prototype for sending each
  // message type, which call this function in turn.
  Protocol.prototype._sendMessage = function (
    typeName,
    data,
    callback
  ) {
    assert(
      messageTypesByName.hasOwnProperty(typeName),
      'unknown message type: ' + typeName
    )
    assert(
      typeof callback === 'function',
      'callback must be function'
    )
    var type = messageTypesByName[typeName]
    try {
      assert(type.validate(data))
      assert(type.verify.call(this, data))
    } catch (error) {
      var moreInformativeError = new Error('invalid ' + typeName)
      moreInformativeError.validationErrors = type.validate.errors
      throw moreInformativeError
    }
    this._encode(type.prefix, data, callback)
  }

  Protocol.prototype.destroy = function (error) {
    var self = this
    /* istanbul ignore if */
    if (self.destroyed) return
    self.destroyed = true
    if (error) self.emit('error', error)
    self._cleanup()
    self.emit('close')
  }

  Protocol.prototype._cleanup = function () {
    var self = this
    self._encoderStream.end()
    if (encrypt) {
      /* istanbul ignore next */
      if (self._sendingCipher) {
        self._sendingCipher.final()
        self._sendingCipher = null
      }
      /* istanbul ignore next */
      if (self._receivingCipher) {
        self._receivingCipher.final()
        self._receivingCipher = null
      }
    }
  }

  // Encode a message tuple.
  Protocol.prototype._encode = function (prefix, data, callback) {
    var tuple = [prefix]
    if (sign) {
      var dataBuffer = Buffer.from(stableStringify(data), 'utf8')
      var signature = Buffer.alloc(SIGN_BYTES)
      sodium.crypto_sign_detached(
        signature,
        dataBuffer,
        this.secretKey
      )
      tuple.push(signature.toString('hex'))
    }
    tuple.push(data)
    this._encoderStream.write(
      // Note that we use built-in JSON.stringify, not
      // stable stringify. Our peer can stable-stringify the
      // message body to verify signature.
      Buffer.from(JSON.stringify(tuple), 'utf8'),
      callback
    )
  }

  // Check a tuple's signature.
  Protocol.prototype._validSignature = function (signature, data) {
    return sodium.crypto_sign_verify_detached(
      Buffer.from(signature, 'hex'),
      // Note that we use stable-stringify for verifying
      // signatures. JSON.stringify could serialize object
      // properties in any order.
      Buffer.from(stableStringify(data)),
      Buffer.from(this.publicKey, 'hex')
    )
  }

  // Parse a message tuple.
  Protocol.prototype._parse = function (message, callback) {
    try {
      var parsed = JSON.parse(message)
    } catch (error) {
      return callback(new Error('invalid JSON'))
    }
    if (!validTuple(parsed)) {
      return callback(new Error('invalid tuple'))
    }
    // The first tuple element is always the type prefix.
    var prefix = parsed[0]
    // If we're signing, the second element will be a signature.
    // Message body always comes last.
    var body, signature
    if (sign) {
      signature = parsed[1]
      body = parsed[2]
    } else {
      body = parsed[1]
    }

    // Handle handshake messages.
    if (prefix === HANDSHAKE_PREFIX) {
      if (!validHandshake(body)) {
        return callback(new Error('invalid handshake'))
      }
      if (version !== body.version) {
        var error = new Error('version mismatch')
        error.version = body.version
        return callback(error)
      }
      if (this._receivedHandshake) {
        return callback(new Error('extra handshake'))
      }
      if (encrypt) {
        this._receivingNonce = Buffer.from(body.nonce, 'hex')
        this._receivingCipher = initializeCipher(
          this._receivingNonce,
          this._encryptionKey
        )
      }
      this._receivedHandshake = true
      this.emit('handshake')
      return callback()
    }

    // Check signatures.
    if (sign && !this._validSignature(signature, body)) {
      return callback(new Error('invalid signature'))
    }

    // Handle protocol-defined message types.
    var type = messageTypesByPrefix[prefix]
    if (
      !type ||
      !type.validate(body) ||
      !type.verify.call(this, body)
    ) {
      var messageBodyError = new Error('invalid message body')
      messageBodyError.prefix = prefix
      messageBodyError.body = body
      return callback(messageBodyError)
    }
    this.emit(type.name, body)
    callback()
  }

  return Protocol
}

function initializeCipher (nonce, secretKey) {
  assert(Buffer.isBuffer(nonce))
  assert(nonce.byteLength === STREAM_NONCEBYTES)
  assert(Buffer.isBuffer(secretKey))
  assert(secretKey.byteLength === STREAM_KEYBYTES)
  return sodium.crypto_stream_xor_instance(nonce, secretKey)
}

function returnTrue () {
  return true
}

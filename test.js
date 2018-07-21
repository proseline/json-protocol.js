var lengthPrefixedStream = require('length-prefixed-stream')
var makeProtocol = require('./')
var sodium = require('sodium-universal')
var tape = require('tape')

var appleAndOrangeMessages = {
  apple: {
    schema: {
      type: 'string',
      const: 'apple',
    },
  },
  orange: {
    schema: {
      type: 'string',
      const: 'orange',
    },
  },
}

var FruitProtocol = makeProtocol({
  version: 1,
  encrypt: true,
  messages: appleAndOrangeMessages,
})

tape('apple and orange', function(test) {
  testAppleAndOrange(FruitProtocol, test)
})

var UnencryptedFruitProtocol = makeProtocol({
  version: 1,
  encrypt: false,
  sign: false,
  messages: appleAndOrangeMessages,
})

tape('unencrypted apple and orange', function(test) {
  testAppleAndOrange(UnencryptedFruitProtocol, test)
})

var SignedFruitProtocol = makeProtocol({
  version: 1,
  encrypt: false,
  sign: true,
  messages: appleAndOrangeMessages,
})

tape('signed apple and orange', function(test) {
  testAppleAndOrange(SignedFruitProtocol, test)
})

var EncryptedSignedFruitProtocol = makeProtocol({
  version: 1,
  encrypt: true,
  sign: true,
  messages: appleAndOrangeMessages,
})

tape('encrypted and signed apple and orange', function(test) {
  testAppleAndOrange(EncryptedSignedFruitProtocol, test)
})

function testAppleAndOrange(protocol, test) {
  test.plan(8)

  var encryptionKey = randomEncryptionKey()
  var seed = randomSeed()

  var anna = protocol({ encryptionKey, seed })
  anna.handshake(function(error) {
    test.ifError(error, 'anna sent handshake')
  })
  anna.once('handshake', function() {
    test.pass('anna received handshake')
    anna.once('apple', function(body) {
      test.equal(body, 'apple', 'anna received apple')
    })
    anna.orange('orange', function(error) {
      test.ifError(error, 'anna sent orange')
    })
  })

  var bob = protocol({ encryptionKey, seed })
  bob.handshake(function(error) {
    test.ifError(error, 'bob sent handshake')
  })
  bob.once('handshake', function() {
    test.pass('bob received handshake')
    bob.once('orange', function(body) {
      test.equal(body, 'orange', 'bob received orange')
    })
    bob.apple('apple', function(error) {
      test.ifError(error, 'bob sent apple')
    })
  })

  anna.pipe(bob).pipe(anna)
}

tape('multiple messages', function(test) {
  test.plan(6)

  var encryptionKey = randomEncryptionKey()

  var anna = FruitProtocol({ encryptionKey })
  anna.handshake(function(error) {
    test.ifError(error, 'anna sent handshake')
    anna.on('apple', function() {
      test.pass('anna received apple')
    })
    anna.on('orange', function() {
      test.pass('anna received orange')
    })
  })

  var bob = FruitProtocol({ encryptionKey })
  bob.handshake(function(error) {
    test.ifError(error, 'bob sent handshake')
    bob.apple('apple', function(error) {
      test.ifError(error, 'bob sent handshake')
    })
    bob.orange('orange', function(error) {
      test.ifError(error, 'bob sent handshake')
    })
  })

  anna.pipe(bob).pipe(anna)
})

tape('version conflict', function(test) {
  test.plan(6)

  var Version1 = makeProtocol({
    version: 1,
    encrypt: true,
    messages: {
      hello: { schema: { type: 'string', const: 'hello' } },
    },
  })

  var Version2 = makeProtocol({
    version: 2,
    encrypt: true,
    messages: {
      howdy: { schema: { type: 'string', const: 'howdy' } },
    },
  })

  var encryptionKey = randomEncryptionKey()

  var anna = Version1({ encryptionKey }).once('error', function(
    error
  ) {
    test.equal(error.message, 'version mismatch')
    test.equal(error.version, 2)
  })
  anna.handshake(function(error) {
    test.ifError(error, 'anna sent handshake')
  })

  var bob = Version2({ encryptionKey }).once('error', function(
    error
  ) {
    test.equal(error.message, 'version mismatch')
    test.equal(error.version, 1)
  })
  bob.handshake(function(error) {
    test.ifError(error, 'anna sent handshake')
  })

  anna.pipe(bob).pipe(anna)
})

tape('double handshake', function(test) {
  var encryptionKey = randomEncryptionKey()
  var anna = FruitProtocol({ encryptionKey })
  anna.handshake(function(error) {
    test.ifError(error)
    anna.handshake(function(error) {
      test.equal(error.message, 'already sent handshake')
      test.end()
    })
  })
})

tape('invalid message', function(test) {
  var encryptionKey = randomEncryptionKey()
  var anna = FruitProtocol({ encryptionKey })
  test.throws(
    function() {
      anna.apple('orange', function() {
        /* pass */
      })
    },
    'invalid apple',
    'invalid apple'
  )
  test.end()
})

tape('verify', function(test) {
  var ProtocolWithValid = makeProtocol({
    version: 1,
    encrypt: true,
    messages: {
      hello: {
        schema: { type: 'string' },
        verify: function(body) {
          return body === 'hello'
        },
      },
    },
  })
  var anna = ProtocolWithValid({
    encryptionKey: randomEncryptionKey(),
  })
  test.throws(function() {
    anna.hello('howdy', function() {
      /* pass */
    })
  }, 'invalid hello')
  test.end()
})

tape('signed without keys', function(test) {
  var SignedProtocol = makeProtocol({
    version: 1,
    encrypt: false,
    sign: true,
    messages: { hello: { schema: { type: 'string' } } },
  })
  test.throws(
    function() {
      SignedProtocol({ encryptionKey: randomEncryptionKey() })
    },
    /must provide/,
    'throws on init'
  )
  test.end()
})

tape('signed with key pair', function(test) {
  var SignedProtocol = makeProtocol({
    version: 1,
    encrypt: false,
    sign: true,
    messages: { hello: { schema: { type: 'string' } } },
  })
  var keyPair = randomKeyPair()
  test.doesNotThrow(function() {
    SignedProtocol({
      publicKey: keyPair.publicKey,
      secretKey: keyPair.secretKey,
    })
  }, 'no exception')
  test.end()
})

tape('encrypted without key', function(test) {
  var EncryptedProtocol = makeProtocol({
    version: 1,
    encrypt: true,
    messages: { hello: { schema: { type: 'string' } } },
  })
  test.throws(
    function() {
      EncryptedProtocol({ seed: randomSeed() })
    },
    /encryptionKey/,
    'throws on init'
  )
  test.end()
})

tape('invalid handshake', function(test) {
  var instance = UnencryptedFruitProtocol({})
  instance.once('error', function(error) {
    test.equal(error.message, 'invalid handshake')
    test.end()
  })
  var lps = lengthPrefixedStream.encode()
  lps.pipe(instance)
  lps.write(JSON.stringify([0, 'blah']))
})

tape('invalid JSON', function(test) {
  var instance = UnencryptedFruitProtocol({})
  instance.once('error', function(error) {
    test.equal(error.message, 'invalid JSON')
    test.end()
  })
  var lps = lengthPrefixedStream.encode()
  lps.pipe(instance)
  lps.write('invalid')
})

tape('invalid message', function(test) {
  var instance = UnencryptedFruitProtocol({})
  instance.once('error', function(error) {
    test.equal(error.message, 'invalid tuple')
    test.end()
  })
  var lps = lengthPrefixedStream.encode()
  lps.pipe(instance)
  lps.write(JSON.stringify({ prefix: 0, body: 'string' }))
})

tape('extra handshake', function(test) {
  var instance = UnencryptedFruitProtocol({})
  instance.once('error', function(error) {
    test.equal(error.message, 'extra handshake')
    test.end()
  })
  var lps = lengthPrefixedStream.encode()
  lps.pipe(instance)
  lps.write(JSON.stringify([0, { version: 1 }]))
  lps.write(JSON.stringify([0, { version: 1 }]))
})

function randomEncryptionKey() {
  var key = Buffer.alloc(32)
  sodium.randombytes_buf(key)
  return key
}

function randomSeed() {
  var seed = Buffer.alloc(sodium.crypto_sign_SEEDBYTES)
  sodium.randombytes_buf(seed)
  return seed
}

function randomKeyPair() {
  var keyPair = {
    publicKey: Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES),
    secretKey: Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES),
  }
  sodium.crypto_sign_keypair(keyPair.publicKey, keyPair.secretKey)
  return keyPair
}

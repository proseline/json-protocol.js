var makeProtocol = require("./");
var sodium = require("sodium-universal");
var tape = require("tape");

tape("apple and orange", function(test) {
  test.plan(8);

  var Protocol = makeProtocol({
    version: 1,
    messages: {
      apple: {
        schema: {
          type: "string",
          const: "apple"
        }
      },
      orange: {
        schema: {
          type: "string",
          const: "orange"
        }
      }
    }
  });

  var replicationKey = Buffer.alloc(32);
  sodium.randombytes_buf(replicationKey);

  var anna = Protocol({ replicationKey });
  anna.handshake(function(error) {
    test.ifError(error, "anna sent handshake");
  });
  anna.once("handshake", function() {
    test.pass("anna received handshake");
    anna.once("apple", function(body) {
      test.equal(body, "apple", "anna received apple");
    });
    anna.orange("orange", function(error) {
      test.ifError(error, "anna sent orange");
    });
  });

  var bob = Protocol({ replicationKey });
  bob.handshake(function(error) {
    test.ifError(error, "bob sent handshake");
  });
  bob.once("handshake", function() {
    test.pass("bob received handshake");
    bob.once("orange", function(body) {
      test.equal(body, "orange", "bob received orange");
    });
    bob.apple("apple", function(error) {
      test.ifError(error, "bob sent apple");
    });
  });

  anna.pipe(bob).pipe(anna);
});

tape("version conflict", function(test) {
  test.plan(6);

  var Version1 = makeProtocol({
    version: 1,
    messages: { hello: { schema: { type: "string", const: "hello" } } }
  });

  var Version2 = makeProtocol({
    version: 2,
    messages: { howdy: { schema: { type: "string", const: "howdy" } } }
  });

  var replicationKey = Buffer.alloc(32);
  sodium.randombytes_buf(replicationKey);

  var anna = Version1({ replicationKey }).once("error", function(error) {
    test.equal(error.message, "version mismatch");
    test.equal(error.version, 2);
  });
  anna.handshake(function(error) {
    test.ifError(error, "anna sent handshake");
  });

  var bob = Version2({ replicationKey }).once("error", function(error) {
    test.equal(error.message, "version mismatch");
    test.equal(error.version, 1);
  });
  bob.handshake(function(error) {
    test.ifError(error, "anna sent handshake");
  });

  anna.pipe(bob).pipe(anna);
});

tape("invalid message", function(test) {
  var Protocol = makeProtocol({
    version: 1,
    messages: { apple: { schema: { type: "string", const: "apple" } } }
  });

  var replicationKey = Buffer.alloc(32);
  sodium.randombytes_buf(replicationKey);

  var anna = Protocol({ replicationKey });
  test.throws(function() {
    anna.apple("orange", function() {
      /* pass */
    });
  }, "invalid apple");

  test.end();
});

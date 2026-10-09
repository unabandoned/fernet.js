var test = require('node:test');
var assert = require('node:assert');
var fernet = require('../fernet');

var testData = require('./fixtures/generate.json')[0];

test('fernet.Token contains a version', function () {
  var token = new fernet.Token();
  assert.strictEqual(token.version, 128);
});

test('fernet.Token.prototype.encode', async function (t) {
  var secret = new fernet.Secret(testData.secret);

  await t.test('encode(message)', function () {
    var token = new fernet.Token({ secret: secret, iv: testData.iv, time: testData.now });
    token.encode(testData.src);
    assert.strictEqual(token.toString(), testData.token);
  });

  await t.test('token.encode() makes token.toString() return the token', function () {
    var token = new fernet.Token({
      secret: secret, iv: testData.iv, time: testData.now, message: testData.src
    });
    token.encode();
    assert.strictEqual(token.toString(), testData.token);
  });

  await t.test('encode() returns the token as a String', function () {
    var token = new fernet.Token({ secret: secret, iv: testData.iv, time: testData.now });
    assert.strictEqual(token.encode(testData.src), testData.token);
  });

  await t.test('uses the IV it is given, not just its indices', function () {
    var iv = [255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240];
    var token = new fernet.Token({ secret: secret, iv: iv, time: testData.now });
    token.encode(testData.src);
    assert.strictEqual(token.ivHex, 'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0');
    var decoded = new fernet.Token({ secret: secret, token: token.toString(), ttl: 0 });
    assert.strictEqual(decoded.decode(), testData.src);
    assert.strictEqual(decoded.ivHex, token.ivHex);
  });

  await t.test('randomly generates IV if one is not passed in', function () {
    var token = new fernet.Token({ secret: secret, time: testData.now });
    var tokenString = token.encode(testData.src);
    assert.notStrictEqual(tokenString, testData.token);
    var tokenString2 = token.encode(testData.src);
    assert.notStrictEqual(tokenString, tokenString2);
  });

  await t.test('time defaults to Date.now()', function () {
    var token = new fernet.Token({ secret: secret });
    var cipherText = token.encode('foo');
    assert.strictEqual(token.decode(cipherText), 'foo');
  });

  await t.test('round-trips multi-byte UTF-8', function () {
    var message = 'héllo, wörld ☃ 🔑';
    var token = new fernet.Token({ secret: secret });
    assert.strictEqual(token.decode(token.encode(message)), message);
  });
});

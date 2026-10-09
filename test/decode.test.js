var test = require('node:test');
var assert = require('node:assert');
var fernet = require('../fernet');

var testData = require('./fixtures/generate.json')[0];
var verifyData = require('./fixtures/verify.json');

var unacceptableClockSkewTestData = {
  token: 'gAAAAAAdwStRAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAnja1xKYyhd-Y6mSkTOyTGJmw2Xc2a6kBd-iX9b_qXQcw==',
  now: '1985-10-26T01:20:01-07:00',
  secret: 'cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4='
};

test('fernet.Token.prototype.decode', async function (t) {
  var _fernet = new fernet({ ttl: 0 });
  var secret = new fernet.Secret(testData.secret);

  await t.test('decode()', function () {
    var token = new _fernet.Token({ secret: secret, token: testData.token });
    assert.strictEqual(token.decode(), 'hello');
    assert.strictEqual(token.toString(), 'hello');
  });

  await t.test('decode(token)', function () {
    var token = new _fernet.Token({ secret: secret });
    assert.strictEqual(token.decode(testData.token), 'hello');
    assert.strictEqual(token.toString(), 'hello');
  });

  await t.test('decode(token) with top-level secret', function () {
    var f = new fernet({ secret: testData.secret, ttl: 0 });
    var token = new f.Token();
    assert.strictEqual(token.decode(testData.token), 'hello');
    assert.strictEqual(token.toString(), 'hello');
  });

  await t.test('recovers version', function () {
    var token = new _fernet.Token({ secret: secret, token: testData.token, version: 1 });
    assert.strictEqual(token.version, 1);
    token.decode();
    assert.strictEqual(token.version, 128);
  });

  await t.test('recovers time', function () {
    var token = new _fernet.Token({ secret: secret, token: testData.token });
    token.decode();
    var now = new Date(Date.parse(testData.now));
    assert.strictEqual(token.time.toUTCString(), now.toUTCString());
  });

  await t.test('recovers iv', function () {
    var token = new _fernet.Token({ secret: secret, token: testData.token });
    token.decode();
    assert.strictEqual(token.ivHex, fernet.ArrayToHex(testData.iv));
  });

  await t.test('recovers hmac', function () {
    var token = new _fernet.Token({ secret: secret, token: testData.token });
    token.decode();
    var computedHmac = fernet.createHmac(secret.signingKey, fernet.timeBytes(token.time), token.iv, token.cipherText);
    assert.strictEqual(token.hmacHex, fernet.bytesToHex(computedHmac));
  });

  await t.test('inherits parent TTL', function () {
    var f = new fernet({ ttl: 1 });
    var token = new f.Token({ secret: secret, token: testData.token });
    assert.throws(function () { token.decode(); }, /Invalid Token: TTL/);
  });

  await t.test('raises new Error("Invalid Token: TTL") on invalid ttl', function () {
    var token = new fernet.Token({ secret: secret, token: testData.token, ttl: 1 });
    assert.throws(function () { token.decode(); }, /Invalid Token: TTL/);
  });

  await t.test('raises new Error("Invalid version") on wrong version byte', function () {
    var tokenHex = fernet.decode64toHex(testData.token);
    var dirtyToken = '01' + tokenHex.slice(fernet.hexBits(8));
    var token = fernet.urlsafe(fernet.bytesToBase64(fernet.hexToBytes(dirtyToken)));
    var t2 = new _fernet.Token({ secret: secret });
    assert.throws(function () { t2.decode(token); }, /Invalid version/);
  });

  await t.test('raises new Error("Invalid version") on empty input', function () {
    var t2 = new _fernet.Token({ secret: secret, token: '' });
    assert.throws(function () { t2.decode(); }, /Invalid version/);
  });

  await t.test('raises new Error("Invalid Token: HMAC") on wrong Hmac', function () {
    var s = testData.token;
    var i = s.length - 5;
    var mutation = String.fromCharCode(s.charCodeAt(i) + 1);
    var dirtyHmacString = s.slice(0, i) + mutation + s.slice(i + 1);
    var token = new _fernet.Token({ secret: secret, token: dirtyHmacString });
    assert.throws(function () { token.decode(); }, /Invalid Token: HMAC/);
  });

  await t.test('raises new Error("far-future timestamp") on unacceptable clock skew', function (tt) {
    var token = new fernet.Token({
      secret: new fernet.Secret(unacceptableClockSkewTestData.secret),
      token: unacceptableClockSkewTestData.token,
      ttl: 1
    });
    tt.mock.timers.enable({ apis: ['Date'], now: Date.parse(unacceptableClockSkewTestData.now) });
    assert.throws(function () { token.decode(); }, /far-future timestamp/);
  });
});

test('fernet spec verify.json', async function (t) {
  for (var v of verifyData) {
    await t.test(v.token, function (tt) {
      tt.mock.timers.enable({ apis: ['Date'], now: Date.parse(v.now) });
      var token = new fernet.Token({ secret: new fernet.Secret(v.secret), token: v.token, ttl: v.ttl_sec });
      assert.strictEqual(token.decode(), v.src);
    });
  }
});

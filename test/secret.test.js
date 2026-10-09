var test = require('node:test');
var assert = require('node:assert');
var fernet = require('../fernet');

test('fernet.Secret', async function (t) {
  var secret64 = 'cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=';
  var signingKeyHex = '730ff4c7af3d46923e8ed451ee813c87';
  var encryptionKeyHex = 'f790b0a226bc96a92de49b5e9c05e1ee';
  var secret = new fernet.Secret(secret64);

  await t.test('secret.signingKeyHex', function () {
    assert.strictEqual(secret.signingKeyHex, signingKeyHex);
  });

  await t.test('secret.signingKey', function () {
    assert.deepStrictEqual(secret.signingKey, fernet.hexToBytes(signingKeyHex));
  });

  await t.test('secret.encryptionKeyHex', function () {
    assert.strictEqual(secret.encryptionKeyHex, encryptionKeyHex);
  });

  await t.test('secret.encryptionKey', function () {
    assert.deepStrictEqual(secret.encryptionKey, fernet.hexToBytes(encryptionKeyHex));
  });

  await t.test('accepts standard base64 as well as url-safe', function () {
    var standard = new fernet.Secret(secret64.replace(/-/g, '+').replace(/_/g, '/'));
    assert.strictEqual(standard.signingKeyHex, signingKeyHex);
    assert.strictEqual(standard.encryptionKeyHex, encryptionKeyHex);
  });

  await t.test('raises "new Error(\'Secret must be 32 url-safe base64-encoded bytes.\')" on wrong secret', function () {
    assert.throws(function () {
      new fernet.Secret('not a good secret');
    }, /Secret must be 32 url-safe base64-encoded bytes\./);
  });
});

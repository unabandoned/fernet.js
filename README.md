# Fernet.js

![ci status](https://github.com/unabandoned/fernet.js/actions/workflows/ci.yml/badge.svg?branch=master)

Javascript implementation of <a href="https://github.com/kr/fernet-spec">Fernet symmetric encryption</a>.

Fernet is an opinionated way of using AES and HMAC authentication that makes
shared-secret symmetric encryption simpler for communicating applications.

This is `@unabandoned/fernet`, a maintained fork of
[`fernet`](https://github.com/csquared/fernet.js). It works unchanged in
Node (22.12+) and in browsers or bundlers: AES-CBC and HMAC-SHA256 come from
[`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers) and
[`@noble/hashes`](https://github.com/paulmillr/noble-hashes), and IVs from
`globalThis.crypto.getRandomValues`, so it needs no Node built-ins and no
`crypto` polyfill.

Keys, IVs, cipher text and HMACs are `Uint8Array`s (the upstream package used
`CryptoJS.lib.WordArray`); the `...Hex` string properties are unchanged.

## WARNING

[It's generally *never* considered safe to encrypt data in the browser.](http://www.matasano.com/articles/javascript-cryptography/)

However, you can use this library to encrypt/decrypt data server-side and decrypt data on a client.

That being said, the only randomness used by this library without your control is a call to
`globalThis.crypto.getRandomValues` to generate IVs (the Web Crypto CSPRNG, in Node and in browsers).

If you're planning on generating the secrets in the browser do yourself a favor and get an audit.

## Use

```sh
npm install @unabandoned/fernet
```

```javascript
var fernet = require('@unabandoned/fernet');
```

To keep existing `require('fernet')` calls working, install it under the old
name: `npm install fernet@npm:@unabandoned/fernet`.

## Fernet

### fernet.setSecret(string)

Sets the `secret` at the top level for all further Tokens made
from this instance of Fernet.

### fernet.ttl = seconds

Sets the `ttl` at the top level for all further Tokens made
from this instance of Fernet.

## Secret

### Generating a secret

    Generating appropriate secrets is beyond the scope of `Fernet`, but you should
    generate it using `/dev/random` in a *nix. To generate a base64-encoded 256 bit
    (32 byte) random sequence, try:

    dd if=/dev/urandom bs=32 count=1 2>/dev/null | openssl base64

### new fernet.Secret(string)

```javascript
  var secret = new fernet.Secret("cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=");
  /*
    {
      signingKeyHex: '730ff4c7af3d46923e8ed451ee813c87',
      signingKey: Uint8Array(16),
      encryptionKeyHex: 'f790b0a226bc96a92de49b5e9c05e1ee',
      encryptionKey: Uint8Array(16)
    }
  */
```

## Token

## new fernet.Token(options)

Options:

- `secret`: a `fernet.Secret` object
- `token`: a Fernet-encoded String
- `ttl`: seconds of ttl

For testing:

- `time`: Date object
- `iv`: Array of Integers

### Token.prototype.encode
```javascript
//Have to include time and iv to make it deterministic.
//Normally time would default to (new Date()) and iv to something random.
var token = new fernet.Token({
  secret: secret,
  time: Date.parse(1),
  iv: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
})
token.encode("Message")
/*
'gAAAAABSO_yhAAECAwQFBgcICQoLDA0OD1PGoFV6wgWZG6AOBfQqevwJT2qKtCZ0EjKy1_TvyxTseR_3ebIF6Ph-xa2QT_tEvg=='
*/
```

### Token.prototype.decode
Include tt
```javascript
var token = new fernet.Token({
  secret: secret,
  token: 'gAAAAABSO_yhAAECAwQFBgcICQoLDA0OD1PGoFV6wgWZG6AOBfQqevwJT2qKtCZ0EjKy1_TvyxTseR_3ebIF6Ph-xa2QT_tEvg==',
  ttl: 0
})
token.decode();

/*
"Message"
*/
```

## Test

    > npm test

Runs the suite with the built-in `node:test` runner, including the
[Fernet spec](https://github.com/fernet/spec) generate and verify vectors.

# Read-TLS-Fingerprint [![Build Status](https://github.com/httptoolkit/read-tls-fingerprint/workflows/CI/badge.svg)](https://github.com/httptoolkit/read-tls-fingerprint/actions) [![Available on NPM](https://img.shields.io/npm/v/read-tls-fingerprint.svg)](https://npmjs.com/package/read-tls-fingerprint)

> _Part of [HTTP Toolkit](https://httptoolkit.tech): powerful tools for building, testing & debugging HTTP(S)_

A pure-JS module to read TLS fingerprints from an incoming socket connection. Tiny, with zero runtime dependencies.

Using this, you can recognize certain TLS clients - e.g. specific browser, cURL, or even the specific versions of a specific programming language a client is using - regardless of the content of the request they send.

See https://httptoolkit.com/blog/tls-fingerprinting-node-js/#how-does-tls-fingerprinting-work for more background on how TLS fingerprinting works.

Be aware that this is _not_ a 100% reliable test. Most clients can modify their TLS fingerprint with a bit of work (though few do). In many cases, it's even possible to mimic another arbitrary fingerprint on demand (e.g. using libraries like [CycleTLS](https://www.npmjs.com/package/cycletls)). Most of the time though, for clients that aren't actively messing with you, the fingerprint will tell you what kind of client is making the connection.

## Docs

The easiest way to use this is with the exported `enableFingerprinting` helper, which can be applied to any `tls.TLSServer` instance, including `https.Server` instances, like so:

```javascript
const https = require('https');
const { enableFingerprinting } = require('read-tls-fingerprint');

const server = new https.Server({ /* your TLS options etc */ });

enableFingerprinting(server);

server.on('request', (request, response) => {
    // In your normal request handler, check `tlsFingerprint` on the request's socket:
    console.log('Received request with fingerprint:', request.socket.tlsFingerprint);
});
```

The `tlsFingerprint` property contains two fields:

* `ja3` - The JA3 hash for the incoming request, e.g. `cd08e31494f9531f560d64c695473da9`
* `data` - The raw data components used to calculate the hash, as an array:
    1. The TLS version number as a Uint16 (771 for TLS 1.2+)
    2. An array of cipher ids (excluding GREASE)
    3. An array of extension ids (excluding GREASE)
    4. An array of supported group ids (excluding GREASE)
    5. An array of supported elliptic curve ids

It is also possible to calculate TLS fingerprints manually. The module exports a few methods for this:

* `getTlsFingerprintData(stream)` - Reads from a stream of incoming TLS client data, returning a promise for the raw fingerprint data, and unshifting the data back into the stream when it's done. Nothing else should attempt to read from the stream until the returned promise resolves (i.e. don't start TLS negotiation until this completes).
* `getTlsFingerprintAsJa3` - Reads from a stream like `getTlsFingerprintData` but returns a promise for the JA3 hash, instead of raw data.
* `calculateJa3FromFingerprintData(data)` - Takes raw TLS fingerprint data, and returns the corresponding JA3 hash.
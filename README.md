# Read-TLS-Client-Hello [![Build Status](https://github.com/httptoolkit/read-tls-client-hello/workflows/CI/badge.svg)](https://github.com/httptoolkit/read-tls-client-hello/actions) [![Available on NPM](https://img.shields.io/npm/v/read-tls-client-hello.svg)](https://npmjs.com/package/read-tls-client-hello)

> _Part of [HTTP Toolkit](https://httptoolkit.tech): powerful tools for building, testing & debugging HTTP(S)_

A pure-JS module to read TLS client hello data and calculate TLS fingerprints from an incoming socket connection. Tiny, with zero runtime dependencies.

Using this, you can analyze incoming TLS connections before you start a full handshake. This gives you the full parsed ClientHello, and TLS fingerprints (JA3/JA4) that let you recognize certain TLS clients (e.g. specific browsers, cURL, or even specific versions of a programming language) regardless of the content of the request they send.

See https://httptoolkit.com/blog/tls-fingerprinting-node-js/#how-does-tls-fingerprinting-work for more background on how TLS fingerprinting works.

Be aware that fingerprinting is _not_ a 100% reliable test. Most clients can modify their TLS fingerprint with a bit of work (though few do). In many cases, it's even possible to mimic another arbitrary fingerprint on demand (e.g. using libraries like [CycleTLS](https://www.npmjs.com/package/cycletls)). Most of the time though, for clients that aren't actively messing with you, the fingerprint will tell you what kind of client is making the connection.

## Docs

### TLS server helper

The easiest way to use this is to use the built-in `trackClientHellos` helper, which can be applied to any `tls.TLSServer` instance, including `https.Server` instances, like so:

```javascript
const https = require('https');
const { trackClientHellos } = require('read-tls-client-hello');

const server = new https.Server({ /* your TLS options etc */ });

trackClientHellos(server); // <-- Automatically track everything on this server

server.on('request', (request, response) => {
    // In your normal request handler, check `tlsClientHello` on the request's socket:
    console.log('Received request with TLS client hello:', request.socket.tlsClientHello);
});
```

A `tlsClientHello` property will be attached to all sockets, containing the parsed ClientHello returned by `readTlsClientHello` (see below), plus `ja3` and `ja4` properties with the TLS fingerprint hashes.

### Reading a TLS client hello

To read all available data from a TLS client hello manually, pass a stream (e.g. a `net.Socket`) to the exported `readTlsClientHello(stream)`, before the TLS handshake (or any other processing) starts. This returns a promise containing all data parsed from the client hello.

This method reads the initial data from the socket, parses it, and then unshifts it back into the socket, so that once the returned promise resolves the stream can be used like new, to start a normal TLS session using the same client hello.

If parsing fails, this method will throw an error, but will still ensure all data is returned to the socket first, so that non-TLS streams can also be processed as normal.

The returned promise resolves to a `TlsClientHelloMessage` object containing:

* `version` - The ClientHello version field (`0x0303` for TLS 1.2 and 1.3 — for TLS 1.3+, check the `supported_versions` extension for the real negotiated version)
* `random` - 32-byte client random as a Buffer
* `sessionId` - Session ID as a Buffer (0–32 bytes, empty Buffer if absent)
* `cipherSuites` - All cipher suite IDs as a number array, **including** GREASE values
* `compressionMethods` - All compression method IDs as a number array
* `extensions` - Ordered array of parsed extensions (see below)

Each extension in the array has:

* `id` - The numeric extension ID
* `data` - Parsed extension data as an object, or `null` for unknown/unparseable/GREASE extensions

GREASE values are preserved (they're what the client actually sent). The `calculateJa3` and `calculateJa4` functions filter GREASE internally. Use the exported `isGREASE(value)` helper to identify GREASE values yourself.

Extensions with registered parsers return structured data. Flag extensions (like `extended_master_secret` or `signed_certificate_timestamp`) return `{}`. Unrecognized, unparseable or GREASE extensions return `null`. If an extension parser encounters malformed data, it falls back to `null` rather than failing the entire parse.

Parsed extensions include: `server_name` (SNI), `max_fragment_length`, `status_request`, `supported_groups`, `ec_point_formats`, `signature_algorithms`, `heartbeat`, `application_layer_protocol_negotiation` (ALPN), `status_request_v2`, `signed_certificate_timestamp`, `padding`, `encrypt_then_mac`, `extended_master_secret`, `compress_certificate`, `record_size_limit`, `session_ticket`, `pre_shared_key`, `early_data`, `supported_versions`, `cookie`, `psk_key_exchange_modes`, `post_handshake_auth`, `signature_algorithms_cert`, `key_share`, `application_settings` (ALPS), `encrypted_client_hello` (ECH), and `renegotiation_info`.

### TLS fingerprinting

To calculate TLS fingerprints, there are a few options exported from this module:

* `getTlsFingerprintAsJa3(stream)` - Reads from a stream, just like `readTlsClientHello` above, but returns a promise for the JA3 hash string, e.g. `cd08e31494f9531f560d64c695473da9`.
* `getTlsFingerprintAsJa4(stream)` - Reads from a stream, just like `readTlsClientHello` above, but returns a promise for the JA4 hash string, e.g. `t13d591000_a33745022dd6_1f22a2ca17c4`.
* `calculateJa3(clientHello)` - Takes a parsed `TlsClientHelloMessage` and returns the corresponding JA3 hash.
* `calculateJa4(clientHello)` - Takes a parsed `TlsClientHelloMessage` and returns the corresponding JA4 hash.

### Accessing extension data

Use `getExtensionData(clientHello, id)` to look up a specific extension's parsed data by numeric ID, name, or alias. Returns the parsed data object, `undefined` if the extension is not present, or `null` if it is present but unknown/unparseable (e.g. GREASE).

Names should be the officially registered name from https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml. Convenient aliases are provided for common cases, including `sni`, `alpn`, `alps` and `ech` - PRs for more common aliases welcome.

The API is typed so that with TypeScript only valid names are allowed (although any raw numeric ID can be used), and the return type is specific to the extension requested — e.g. `getExtensionData(hello, 'sni')` returns `{ serverName: string } | null | undefined`.

```javascript
const { readTlsClientHello, getExtensionData } = require('read-tls-client-hello');

const clientHello = await readTlsClientHello(socket);

// Get the server name (SNI)
const sniData = getExtensionData(clientHello, 'sni'); // or 'server_name', or 0x0
const serverName = sniData?.serverName;

// Get ALPN protocols
const alpnData = getExtensionData(clientHello, 'alpn');
const protocols = alpnData?.protocols;

// Get supported TLS versions
const svData = getExtensionData(clientHello, 'supported_versions');
const versions = svData?.versions; // e.g. [0x0304, 0x0303]
```

### Lookup tables

All hello details (extensions, ciphers, etc) are exposed with numeric IDs. Lookup tables map these to human-readable names. All tables are fully typed with `as const`, so known keys return literal values, while unknown keys' values may be undefined.

Forward tables (ID → name) for display:

* `TLS_VERSIONS` - e.g. `0x0303` → `'TLS 1.2'`
* `CIPHER_SUITES` - e.g. `0x1301` → `'TLS_AES_128_GCM_SHA256'`
* `EXTENSIONS` - e.g. `0` → `'server_name'`, `51` → `'key_share'`
* `SUPPORTED_GROUPS` - e.g. `29` → `'x25519'`, `4588` → `'X25519MLKEM768'`
* `SIGNATURE_ALGORITHMS` - e.g. `0x0403` → `'ecdsa_secp256r1_sha256'`
* `EC_POINT_FORMATS` - e.g. `0` → `'uncompressed'`
* `COMPRESSION_METHODS` - e.g. `0` → `'null'`
* `PSK_KEY_EXCHANGE_MODES` - e.g. `1` → `'psk_dhe_ke'`
* `CERTIFICATE_COMPRESSION_ALGORITHMS` - e.g. `2` → `'brotli'`
* `CERTIFICATE_STATUS_TYPES` - e.g. `1` → `'ocsp'`

A reverse table (name → ID) is also available for extensions:

* `EXTENSION_IDS` - e.g. `EXTENSION_IDS.key_share` → `51`, with aliases: `sni` (0), `alpn` (16), `alps` (17513), `ech` (65037)

```javascript
const { CIPHER_SUITES, isGREASE } = require('read-tls-client-hello');

const cipherNames = clientHello.cipherSuites
    .filter(id => !isGREASE(id))
    .map(id => CIPHER_SUITES[id] || `unknown (0x${id.toString(16)})`);
```

These are sourced from the IANA TLS registries and include post-quantum entries (ML-KEM, ML-DSA). Please open a PR to include any missing registered values.
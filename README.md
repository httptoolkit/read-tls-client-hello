# Read-TLS-Fingerprint [![Build Status](https://github.com/httptoolkit/read-tls-fingerprint/workflows/CI/badge.svg)](https://github.com/httptoolkit/read-tls-fingerprint/actions) [![Available on NPM](https://img.shields.io/npm/v/read-tls-fingerprint.svg)](https://npmjs.com/package/read-tls-fingerprint)

> _Part of [HTTP Toolkit](https://httptoolkit.tech): powerful tools for building, testing & debugging HTTP(S)_

A pure-JS module to read TLS fingerprints from an incoming socket connection. Using this, you can recognize certain TLS clients - e.g. specific browser, cURL, or even the specific versions of a specific programming language a client is using - regardless of the content of the request they send.
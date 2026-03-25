import * as path from 'path';
import * as fs from 'fs';
import * as net from 'net';
import * as tls from 'tls';
import * as http from 'http';
import * as https from 'https';
import { makeDestroyable, DestroyableServer } from 'destroyable-server';

import { expect } from 'chai';
import {
    getDeferred,
    streamToBuffer,
    testKey,
    testCert
} from './test-util';

import {
    readTlsClientHello,
    getExtensionData,
    getTlsFingerprintAsJa3,
    getTlsFingerprintAsJa4,
    calculateJa3,
    calculateJa4,
    trackClientHellos,
    isGREASE,
    extensionParsers,
    CIPHER_SUITES,
    EXTENSIONS,
    SUPPORTED_GROUPS,
    SIGNATURE_ALGORITHMS,
    TLS_VERSIONS
} from '../src/index';

import {
    parseMaxFragmentLengthExtension,
    parseStatusRequestV2Extension,
    parseRecordSizeLimitExtension,
    parsePreSharedKeyExtension,
    parseCookieExtension,
    parseHeartbeatExtension,
    parseEncryptedClientHelloExtension,
    parseSignatureAlgorithmsCertExtension,
} from '../src/extension-parsers';

const nodeMajorVersion = parseInt(process.version.slice(1).split('.')[0], 10);
const nodeMinorVersion = parseInt(process.version.slice(1).split('.')[1], 10);

// Node 22.20+ and Node 24+ include ML-KEM support and renegotiation_info extension
const hasNewTlsConfig = nodeMajorVersion >= 24 ||
    (nodeMajorVersion === 22 && nodeMinorVersion >= 20);

interface FingerprintResponse {
    ja3: string;
    ja4: string;
}

describe("Read-TLS-Client-Hello", () => {

    let server: DestroyableServer<net.Server>;

    afterEach(() => server?.destroy().catch(() => {}));

    it("can read Node's fingerprint data", async () => {
        server = makeDestroyable(new net.Server());

        server.listen();
        await new Promise((resolve) => server.on('listening', resolve));

        let incomingSocketPromise = getDeferred<net.Socket>();
        server.on('connection', (socket) => incomingSocketPromise.resolve(socket));

        const port = (server.address() as net.AddressInfo).port;
        tls.connect({
            host: 'localhost',
            port
        }).on('error', () => {}); // Socket will fail, since server never responds, that's OK

        const incomingSocket = await incomingSocketPromise;
        const clientHello = await readTlsClientHello(incomingSocket);

        const ciphers = clientHello.cipherSuites.filter(c => !isGREASE(c));
        const extensionIds = clientHello.extensions.map(e => e.id).filter(id => !isGREASE(id));
        const groups = (clientHello.extensions.find(e => e.id === 0x000A)?.data as any)
            ?.groups.filter((g: number) => !isGREASE(g)) ?? [];
        const curveFormats = (clientHello.extensions.find(e => e.id === 0x000B)?.data as any)
            ?.formats ?? [];

        expect(clientHello.version).to.equal(771); // TLS 1.2 - now set even for TLS 1.3 for backward compat
        expect(ciphers.slice(0, 3)).to.deep.equal([4866, 4867, 4865]);
        if (hasNewTlsConfig) {
            // Node 22.20+ / 24+ adds renegotiation_info extension (65281)
            expect(extensionIds).to.deep.equal([
                65281,
                11,
                10,
                35,
                22,
                23,
                13,
                43,
                45,
                51
            ]);
            // Node 22.20+ / 24+ adds ML-KEM-768 (4588) and has different group order
            expect(groups).to.deep.equal([4588, 29, 23, 30, 24, 25, 256, 257]);
        } else {
            expect(extensionIds).to.deep.equal([
                11,
                10,
                35,
                22,
                23,
                13,
                43,
                45,
                51
            ]);
            expect(groups).to.deep.equal([
                29, 23, 30, 25, 24,
                ...(nodeMajorVersion >= 17 ? [256, 257, 258, 259, 260] : [])
            ]);
        }
        expect(curveFormats).to.deep.equal([0, 1, 2]);
    });

    it("can read Node's client hello data", async () => {
        server = makeDestroyable(new net.Server());

        server.listen();
        await new Promise((resolve) => server.on('listening', resolve));

        let incomingSocketPromise = getDeferred<net.Socket>();
        server.on('connection', (socket) => incomingSocketPromise.resolve(socket));

        const port = (server.address() as net.AddressInfo).port;
        tls.connect({
            host: 'localhost',
            port
        }).on('error', () => {}); // Socket will fail, since server never responds, that's OK

        const incomingSocket = await incomingSocketPromise;
        const clientHello = await readTlsClientHello(incomingSocket);

        // No SNI or ALPN set for pure TLS like this
        const sniExt = clientHello.extensions.find(e => e.id === 0x0000);
        expect(sniExt).to.equal(undefined);
        const alpnExt = clientHello.extensions.find(e => e.id === 0x0010);
        expect(alpnExt).to.equal(undefined);
    });

    it("can read Node's JA3 fingerprint", async () => {
        server = makeDestroyable(new net.Server());

        server.listen();
        await new Promise((resolve) => server.on('listening', resolve));

        let incomingSocketPromise = getDeferred<net.Socket>();
        server.on('connection', (socket) => incomingSocketPromise.resolve(socket));

        const port = (server.address() as net.AddressInfo).port;
        https.request({
            host: 'localhost',
            port
        }).on('error', () => {}); // Socket will fail, since server never responds, that's OK

        const incomingSocket = await incomingSocketPromise;
        const fingerprint = await getTlsFingerprintAsJa3(incomingSocket);

        expect(fingerprint).to.be.oneOf([
            '398430069e0a8ecfbc8db0778d658d77', // Node 12 - 16
            '0cce74b0d9b7f8528fb2181588d23793', // Node 17 - 22.18, 23.x
            '944d1e1858cd278718f8a46b65d3212f' // Node 22.20+, 24+
        ]);
    });

    it("can read Node's JA4 fingerprint", async () => {
        server = makeDestroyable(new net.Server());

        server.listen();
        await new Promise((resolve) => server.on('listening', resolve));

        let incomingSocketPromise = getDeferred<net.Socket>();
        server.on('connection', (socket) => incomingSocketPromise.resolve(socket));

        const port = (server.address() as net.AddressInfo).port;
        https.request({
            host: 'localhost',
            port
        }).on('error', () => {}); // Socket will fail, since server never responds, that's OK

        const incomingSocket = await incomingSocketPromise;
        const fingerprint = await getTlsFingerprintAsJa4(incomingSocket);

        expect(fingerprint).to.be.oneOf([
            't13d591000_a33745022dd6_5ac7197df9d2', // Node 12 - 16
            't13d591000_a33745022dd6_1f22a2ca17c4', // Node 17 - 22.18, 23.x
            't13d521100_b262b3658495_8e6e362c5eac' // Node 22.20+, 24+
        ]);
    });

    it("calculates the same fingerprint as testserver.host", async function () {
        server = makeDestroyable(new net.Server());

        server.listen();
        await new Promise((resolve) => server.on('listening', resolve));

        let incomingSocketPromise = getDeferred<net.Socket>();
        server.on('connection', (socket) => incomingSocketPromise.resolve(socket));

        const port = (server.address() as net.AddressInfo).port;
        https.request({
            host: 'localhost',
            port
        }).on('error', () => {}); // Socket will fail, since server never responds, that's OK

        const incomingSocket = await incomingSocketPromise;
        const clientHello = await readTlsClientHello(incomingSocket);
        const ourJa3 = await getTlsFingerprintAsJa3(incomingSocket);
        const ourJa4 = calculateJa4(clientHello);

        const remoteFingerprints = await new Promise<FingerprintResponse>((resolve, reject) => {
            const response = https.get('https://testserver.host/tls/fingerprint');
            response.on('response', async (resp) => {
                if (resp.statusCode !== 200) reject(new Error(`Unexpected ${resp.statusCode} from testserver.host`));

                try {
                    const rawData = await streamToBuffer(resp);
                    const data = JSON.parse(rawData.toString()) as FingerprintResponse;
                    resolve(data);
                } catch (e) {
                    reject(e);
                }
            });
            response.on('error', reject);
        });

        // Check both JA3 and JA4 hashes
        expect(ourJa3).to.equal(remoteFingerprints.ja3);
        expect(ourJa4).to.equal(remoteFingerprints.ja4);
    });

    it("can capture the server name from a Chrome request", async () => {
        const incomingData = fs.createReadStream(path.join(__dirname, 'fixtures', 'chrome-tls-connect.bin'));

        const clientHello = await readTlsClientHello(incomingData);
        const sniData = clientHello.extensions.find(e => e.id === 0x0000)?.data as any;
        expect(sniData.serverName).to.equal('localhost');
    });

    it("can capture ALPN protocols from a Chrome request", async () => {
        const incomingData = fs.createReadStream(path.join(__dirname, 'fixtures', 'chrome-tls-connect.bin'));

        const clientHello = await readTlsClientHello(incomingData);
        const alpnData = clientHello.extensions.find(e => e.id === 0x0010)?.data as any;
        expect(alpnData.protocols).to.deep.equal([
            'h2',
            'http/1.1'
        ]);
    });

    it("can calculate the correct TLS fingerprint from a Chrome request", async () => {
        const incomingData = fs.createReadStream(path.join(__dirname, 'fixtures', 'chrome-tls-connect.bin'));

        const clientHello = await readTlsClientHello(incomingData);

        const ciphers = clientHello.cipherSuites.filter(c => !isGREASE(c));
        const extensionIds = clientHello.extensions.map(e => e.id).filter(id => !isGREASE(id));
        const groups = (clientHello.extensions.find(e => e.id === 0x000A)?.data as any)
            ?.groups.filter((g: number) => !isGREASE(g)) ?? [];
        const curveFormats = (clientHello.extensions.find(e => e.id === 0x000B)?.data as any)
            ?.formats ?? [];

        expect(clientHello.version).to.equal(771); // TLS 1.2 - now set even for TLS 1.3 for backward compat
        expect(ciphers.slice(0, 3)).to.deep.equal([4865, 4866, 4867]);
        expect(ciphers.length).to.equal(15);
        expect(extensionIds).to.deep.equal([
            0,
            23,
            65281,
            10,
            11,
            35,
            16,
            5,
            13,
            18,
            51,
            45,
            43,
            27,
            17513,
            21
        ]);
        expect(groups).to.deep.equal([29, 23, 24]);
        expect(curveFormats).to.deep.equal([0]);

        const fingerprint = calculateJa3(clientHello);
        expect(fingerprint).to.equal('cd08e31494f9531f560d64c695473da9');
    });

    it("can be manually calculate the fingerprint alongside a real TLS session", async () => {
        const tlsServer = tls.createServer({ key: testKey, cert: testCert })
        server = makeDestroyable(new net.Server());

        server.on('connection', async (socket: any) => {
            socket.tlsFingerprint = await getTlsFingerprintAsJa3(socket);
            tlsServer.emit('connection', socket);
        });

        const tlsSocketPromise = new Promise<tls.TLSSocket>((resolve) =>
            tlsServer.on('secureConnection', (tlsSocket: any) => {
                tlsSocket.tlsFingerprint = tlsSocket._parent.tlsFingerprint;
                resolve(tlsSocket);
            })
        );

        server.listen();
        await new Promise((resolve) => server.on('listening', resolve));

        const port = (server.address() as net.AddressInfo).port;
        tls.connect({
            host: 'localhost',
            ca: [testCert],
            port
        });

        const tlsSocket: any = await tlsSocketPromise;
        const fingerprint = tlsSocket.tlsFingerprint;
        expect(fingerprint).to.be.oneOf([
            '76cd17e0dc73c98badbb6ee3752dcf4c', // Node 12 - 16
            '6521bd74aad3476cdb3daa827288ec35', // Node 17 - 22.18, 23.x
            'e29263fb066facf0f3d23ccaf0fe19da' // Node 22.20+, 24+
        ]);
    });

    it("can be parsed automatically with the provided helper", async () => {
        const httpsServer = makeDestroyable(
            trackClientHellos(
                https.createServer({ key: testKey, cert: testCert })
            )
        );
        server = httpsServer;

        const tlsSocketPromise = new Promise<tls.TLSSocket>((resolve) =>
            httpsServer.on('request', (request: http.IncomingMessage) =>
                resolve(request.socket as tls.TLSSocket)
            )
        );

        httpsServer.listen();
        await new Promise((resolve) => httpsServer.on('listening', resolve));

        const port = (httpsServer.address() as net.AddressInfo).port;
        https.get({
            host: 'localhost',
            ca: [testCert],
            port
        }).on('error', () => {}); // No response, we don't care

        const tlsSocket = await tlsSocketPromise;
        const ch = tlsSocket.tlsClientHello!;

        expect(ch.version).to.equal(771);
        expect(ch.cipherSuites.length).to.be.greaterThan(0);
        expect(ch.extensions.length).to.be.greaterThan(0);
        expect(ch.ja3).to.be.a('string');
        expect(ch.ja4).to.be.a('string');
    });

    it("doesn't break non-TLS connections", async () => {
        const httpServer = new http.Server();
        server = makeDestroyable(new net.Server());

        server.on('connection', async (socket: any) => {
            socket.tlsFingerprint = await getTlsFingerprintAsJa3(socket)
                .catch(e => ({ error: e }));
            httpServer.emit('connection', socket);
        });

        httpServer.on('request', (request, response) => {
            expect(request.method).to.equal('GET');
            expect(request.url).to.equal('/test-request-path');

            const fingerprint = (request.socket as any).tlsFingerprint;
            expect(fingerprint.error.message).to.equal(
                "Can't calculate TLS fingerprint - not a TLS stream"
            );

            response.writeHead(200).end();
        });

        server.listen();
        await new Promise((resolve) => server.on('listening', resolve));

        const port = (server.address() as net.AddressInfo).port;
        const req = http.get({ host: 'localhost', port, path: '/test-request-path' });

        const response = await new Promise<http.ServerResponse>((resolve) =>
            req.on('response', resolve)
        );

        expect(response.statusCode).to.equal(200);
    });

    it("can read a TLS v1 fingerprint", async function () {
        if (nodeMajorVersion >= 17) this.skip(); // New Node doesn't support this

        server = makeDestroyable(new net.Server());

        server.listen();
        await new Promise((resolve) => server.on('listening', resolve));

        let incomingSocketPromise = getDeferred<net.Socket>();
        server.on('connection', (socket) => incomingSocketPromise.resolve(socket));

        const port = (server.address() as net.AddressInfo).port;
        tls.connect({
            host: 'localhost',
            port,
            maxVersion: 'TLSv1', // <-- Force old TLS
            minVersion: 'TLSv1'
        }).on('error', () => {}); // Socket will fail, since server never responds, that's OK

        const incomingSocket = await incomingSocketPromise;
        const clientHello = await readTlsClientHello(incomingSocket);

        const ciphers = clientHello.cipherSuites.filter(c => !isGREASE(c));
        const extensionIds = clientHello.extensions.map(e => e.id).filter(id => !isGREASE(id));
        const groups = (clientHello.extensions.find(e => e.id === 0x000A)?.data as any)
            ?.groups.filter((g: number) => !isGREASE(g)) ?? [];
        const curveFormats = (clientHello.extensions.find(e => e.id === 0x000B)?.data as any)
            ?.formats ?? [];

        expect(clientHello.version).to.equal(769); // TLS 1!
        expect(ciphers.slice(0, 3)).to.deep.equal([49162, 49172, 57]);
        expect(extensionIds).to.deep.equal([
            11,
            10,
            35,
            22,
            23
        ]);
        expect(groups).to.deep.equal([29, 23, 30, 25, 24]);
        expect(curveFormats).to.deep.equal([0, 1, 2]);
    });

});

describe("ClientHello parsing", () => {

    it("parses the full clientHello from the Chrome fixture", async () => {
        const incomingData = fs.createReadStream(path.join(__dirname, 'fixtures', 'chrome-tls-connect.bin'));
        const clientHello = await readTlsClientHello(incomingData);

        // Base fields
        expect(clientHello.version).to.equal(0x0303);
        expect(clientHello.random).to.be.instanceOf(Buffer);
        expect(clientHello.random.length).to.equal(32);
        expect(clientHello.sessionId).to.be.instanceOf(Buffer);
        expect(clientHello.sessionId.length).to.equal(32);
        expect(clientHello.compressionMethods).to.deep.equal([0]);

        // Cipher suites include GREASE - first one is 0x4a4a
        expect(isGREASE(clientHello.cipherSuites[0])).to.equal(true);
        // Non-GREASE ciphers start with TLS 1.3 suites
        const nonGreaseCiphers = clientHello.cipherSuites.filter(c => !isGREASE(c));
        expect(nonGreaseCiphers.slice(0, 3)).to.deep.equal([0x1301, 0x1302, 0x1303]);
        expect(nonGreaseCiphers.length).to.equal(15);
        // Total includes GREASE value(s)
        expect(clientHello.cipherSuites.length).to.equal(16);

        // Extensions preserve order and include GREASE
        expect(clientHello.extensions.length).to.equal(18);
        const extIds = clientHello.extensions.map(e => e.id);
        // First extension is GREASE
        expect(isGREASE(extIds[0])).to.equal(true);
        expect(clientHello.extensions[0].data).to.equal(null);
        // Last real extension before trailing GREASE is padding
        expect(extIds[extIds.length - 1]).to.equal(0x0015); // padding
    });

    it("parses Chrome fixture extension data correctly", async () => {
        const incomingData = fs.createReadStream(path.join(__dirname, 'fixtures', 'chrome-tls-connect.bin'));
        const clientHello = await readTlsClientHello(incomingData);

        const extById = new Map(clientHello.extensions.map(e => [e.id, e.data]));

        // SNI
        expect(extById.get(0x0000)).to.deep.equal({ serverName: 'localhost' });

        // Flag extensions return empty objects
        expect(extById.get(0x0017)).to.deep.equal({}); // extended_master_secret
        expect(extById.get(0x0012)).to.deep.equal({}); // signed_certificate_timestamp

        // renegotiation_info
        expect(extById.get(0xFF01)).to.deep.equal({ renegotiatedConnectionLength: 0 });

        // supported_groups (includes GREASE)
        const groups = extById.get(0x000A) as { groups: number[] };
        expect(groups.groups.filter(g => !isGREASE(g))).to.deep.equal([29, 23, 24]);
        expect(groups.groups.some(g => isGREASE(g))).to.equal(true);

        // ec_point_formats
        expect(extById.get(0x000B)).to.deep.equal({ formats: [0] });

        // session_ticket (empty = requesting new)
        expect(extById.get(0x0023)).to.deep.equal({ ticketLength: 0 });

        // ALPN
        expect(extById.get(0x0010)).to.deep.equal({ protocols: ['h2', 'http/1.1'] });

        // status_request (OCSP)
        expect(extById.get(0x0005)).to.deep.equal({ statusType: 1 });

        // signature_algorithms
        const sigAlgs = extById.get(0x000D) as { algorithms: number[] };
        expect(sigAlgs.algorithms.length).to.be.greaterThan(0);
        expect(sigAlgs.algorithms).to.include(0x0403); // ecdsa_secp256r1_sha256

        // key_share
        const keyShare = extById.get(0x0033) as { entries: Array<{ group: number, keyExchangeLength: number }> };
        expect(keyShare.entries.length).to.be.greaterThan(0);
        const nonGreaseEntries = keyShare.entries.filter(e => !isGREASE(e.group));
        expect(nonGreaseEntries[0].group).to.equal(29); // x25519
        expect(nonGreaseEntries[0].keyExchangeLength).to.equal(32);

        // psk_key_exchange_modes
        expect(extById.get(0x002D)).to.deep.equal({ modes: [1] }); // psk_dhe_ke

        // supported_versions (includes GREASE)
        const versions = extById.get(0x002B) as { versions: number[] };
        expect(versions.versions.filter(v => !isGREASE(v))).to.deep.equal([0x0304, 0x0303]); // TLS 1.3, 1.2

        // compress_certificate
        expect(extById.get(0x001B)).to.deep.equal({ algorithms: [2] }); // brotli

        // ALPS (application_settings)
        expect(extById.get(0x4469)).to.deep.equal({ protocols: ['h2'] });

        // padding
        const padding = extById.get(0x0015) as { paddingLength: number };
        expect(padding.paddingLength).to.be.greaterThan(0);
    });

    it("preserves GREASE in clientHello while calculateJa3 filters it", async () => {
        const incomingData = fs.createReadStream(path.join(__dirname, 'fixtures', 'chrome-tls-connect.bin'));
        const clientHello = await readTlsClientHello(incomingData);

        // clientHello preserves GREASE
        expect(clientHello.cipherSuites.some(c => isGREASE(c))).to.equal(true);
        expect(clientHello.extensions.some(e => isGREASE(e.id))).to.equal(true);

        // JA3 calculation works (internally filters GREASE)
        const ja3 = calculateJa3(clientHello);
        expect(ja3).to.equal('cd08e31494f9531f560d64c695473da9');

        // Non-GREASE counts are smaller than total
        const nonGreaseCiphers = clientHello.cipherSuites.filter(c => !isGREASE(c));
        expect(clientHello.cipherSuites.length).to.be.greaterThan(nonGreaseCiphers.length);
    });

    let server: net.Server & { destroy?: () => Promise<void> };

    afterEach(() => server?.destroy?.().catch(() => {}));

    it("parses clientHello from a live Node TLS connection", async () => {
        const netServer = makeDestroyable(new net.Server());
        server = netServer;

        netServer.listen();
        await new Promise((resolve) => netServer.on('listening', resolve));

        let incomingSocketPromise = getDeferred<net.Socket>();
        netServer.on('connection', (socket) => incomingSocketPromise.resolve(socket));

        const port = (netServer.address() as net.AddressInfo).port;
        tls.connect({ host: 'localhost', port })
            .on('error', () => {});

        const incomingSocket = await incomingSocketPromise;
        const clientHello = await readTlsClientHello(incomingSocket);

        // Structural checks that hold regardless of Node version
        expect(clientHello.version).to.equal(0x0303);
        expect(clientHello.random.length).to.equal(32);
        expect(clientHello.sessionId.length).to.be.within(0, 32);
        expect(clientHello.cipherSuites.length).to.be.greaterThan(0);
        expect(clientHello.compressionMethods).to.deep.equal([0]);
        expect(clientHello.extensions.length).to.be.greaterThan(0);

        // Every extension should have numeric id and either parsed data or null
        for (const ext of clientHello.extensions) {
            expect(ext.id).to.be.a('number');
            if (ext.data !== null) {
                expect(ext.data).to.be.an('object');
            }
        }

        // supported_versions should be present (Node uses TLS 1.3)
        const svExt = clientHello.extensions.find(e => e.id === 0x002B);
        expect(svExt).to.not.be.undefined;
        expect((svExt!.data as any).versions).to.include(0x0304);

        // key_share should be present
        const ksExt = clientHello.extensions.find(e => e.id === 0x0033);
        expect(ksExt).to.not.be.undefined;
        expect((ksExt!.data as any).entries.length).to.be.greaterThan(0);

        // signature_algorithms should be present
        const saExt = clientHello.extensions.find(e => e.id === 0x000D);
        expect(saExt).to.not.be.undefined;
        expect((saExt!.data as any).algorithms.length).to.be.greaterThan(0);
    });

    it("includes clientHello via trackClientHellos", async () => {
        const httpsServer = makeDestroyable(
            trackClientHellos(
                https.createServer({ key: testKey, cert: testCert })
            )
        );
        server = httpsServer;

        const tlsSocketPromise = new Promise<tls.TLSSocket>((resolve) =>
            httpsServer.on('request', (request: http.IncomingMessage) =>
                resolve(request.socket as tls.TLSSocket)
            )
        );

        httpsServer.listen();
        await new Promise((resolve) => httpsServer.on('listening', resolve));

        const port = (httpsServer.address() as net.AddressInfo).port;
        https.get({
            host: 'localhost',
            ca: [testCert],
            port
        }).on('error', () => {});

        const tlsSocket = await tlsSocketPromise;
        const ch = tlsSocket.tlsClientHello!;

        expect(ch).to.not.be.undefined;
        expect(ch.version).to.equal(0x0303);
        expect(ch.random.length).to.equal(32);
        expect(ch.cipherSuites.length).to.be.greaterThan(0);
        expect(ch.extensions.length).to.be.greaterThan(0);
        expect(ch.ja3).to.be.a('string');
        expect(ch.ja4).to.be.a('string');
    });

    it("handles malformed extension data gracefully", async () => {
        // A truncated buffer that will cause most parsers to throw
        const truncated = Buffer.from([0x00]);

        // supported_groups parser expects at least 2 bytes for length + data
        // When called from the main parser, errors fall back to null.
        // We can verify the parser itself throws:
        expect(() => extensionParsers[0x000A]!(truncated)).to.throw();

        // key_share parser with truncated data
        expect(() => extensionParsers[0x0033]!(truncated)).to.throw();
    });
});

describe("Extension parsers (unit tests)", () => {
    // Test parsers not exercised by the Chrome or Node fixtures

    it("parses max_fragment_length", () => {
        const data = Buffer.from([0x03]); // 2^11
        expect(parseMaxFragmentLengthExtension(data)).to.deep.equal({ maxFragmentLength: 3 });
    });

    it("parses status_request_v2", () => {
        // 2-byte total length = 6, then two items:
        // item 1: type=1 (ocsp), length=0, no data
        // item 2: type=2 (ocsp_multi), length=0, no data
        const data = Buffer.from([
            0x00, 0x06, // total length
            0x01, 0x00, 0x00, // type 1, length 0
            0x02, 0x00, 0x00, // type 2, length 0
        ]);
        expect(parseStatusRequestV2Extension(data)).to.deep.equal({ statusTypes: [1, 2] });
    });

    it("parses record_size_limit", () => {
        const data = Buffer.from([0x40, 0x00]); // 16384
        expect(parseRecordSizeLimitExtension(data)).to.deep.equal({ recordSizeLimit: 16384 });
    });

    it("parses pre_shared_key", () => {
        // identities list: length=12, one identity: length=4, 4 bytes data, ticket_age=0x12345678
        const data = Buffer.from([
            0x00, 0x0A, // identities list length
            0x00, 0x04, // identity length
            0xAA, 0xBB, 0xCC, 0xDD, // identity data (opaque)
            0x12, 0x34, 0x56, 0x78, // obfuscated_ticket_age
            // binders would follow but we skip them
        ]);
        const result = parsePreSharedKeyExtension(data) as {
            identities: Array<{ identityLength: number, obfuscatedTicketAge: number }>
        };
        expect(result.identities).to.have.length(1);
        expect(result.identities[0].identityLength).to.equal(4);
        expect(result.identities[0].obfuscatedTicketAge).to.equal(0x12345678);
    });

    it("parses cookie", () => {
        const data = Buffer.from([0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]);
        expect(parseCookieExtension(data)).to.deep.equal({ cookieLength: 5 });
    });

    it("parses heartbeat", () => {
        const data = Buffer.from([0x01]); // peer_allowed_to_send
        expect(parseHeartbeatExtension(data)).to.deep.equal({ mode: 1 });
    });

    it("parses encrypted_client_hello (outer)", () => {
        const data = Buffer.from([
            0x00, // type: outer
            0x00, 0x01, // kdfId: HKDF-SHA256
            0x00, 0x01, // aeadId: AES-128-GCM
            0x42, // configId
            0x00, 0x03, // enc length
            0xAA, 0xBB, 0xCC, // enc data
            0x00, 0x10, // payload length
        ]);
        expect(parseEncryptedClientHelloExtension(data)).to.deep.equal({
            type: 0,
            kdfId: 1,
            aeadId: 1,
            configId: 0x42,
            encLength: 3,
            payloadLength: 16
        });
    });

    it("parses encrypted_client_hello (inner)", () => {
        const data = Buffer.from([0x01]); // type: inner
        expect(parseEncryptedClientHelloExtension(data)).to.deep.equal({ type: 1 });
    });

    it("parses signature_algorithms_cert (same format as signature_algorithms)", () => {
        const data = Buffer.from([
            0x00, 0x04, // list length
            0x04, 0x03, // ecdsa_secp256r1_sha256
            0x08, 0x04, // rsa_pss_rsae_sha256
        ]);
        expect(parseSignatureAlgorithmsCertExtension(data)).to.deep.equal({
            algorithms: [0x0403, 0x0804]
        });
    });
});

describe("Lookup tables", () => {

    it("contain expected well-known values", () => {
        expect(TLS_VERSIONS[0x0303]).to.equal('TLS 1.2');
        expect(TLS_VERSIONS[0x0304]).to.equal('TLS 1.3');

        expect(CIPHER_SUITES[0x1301]).to.equal('TLS_AES_128_GCM_SHA256');
        expect(CIPHER_SUITES[0x1303]).to.equal('TLS_CHACHA20_POLY1305_SHA256');
        expect(CIPHER_SUITES[0xC02C]).to.equal('TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384');

        expect(EXTENSIONS[0]).to.equal('server_name');
        expect(EXTENSIONS[43]).to.equal('supported_versions');
        expect(EXTENSIONS[51]).to.equal('key_share');
        expect(EXTENSIONS[65281]).to.equal('renegotiation_info');
        expect(EXTENSIONS[17513]).to.equal('application_settings');

        expect(SUPPORTED_GROUPS[29]).to.equal('x25519');
        expect(SUPPORTED_GROUPS[23]).to.equal('secp256r1');
        expect(SUPPORTED_GROUPS[4588]).to.equal('X25519MLKEM768');

        expect(SIGNATURE_ALGORITHMS[0x0403]).to.equal('ecdsa_secp256r1_sha256');
        expect(SIGNATURE_ALGORITHMS[0x0804]).to.equal('rsa_pss_rsae_sha256');
        expect(SIGNATURE_ALGORITHMS[0x0807]).to.equal('ed25519');
    });

    it("can resolve all cipher suites from a Chrome ClientHello", async () => {
        const incomingData = fs.createReadStream(path.join(__dirname, 'fixtures', 'chrome-tls-connect.bin'));
        const clientHello = await readTlsClientHello(incomingData);

        const nonGreaseCiphers = clientHello.cipherSuites.filter(c => !isGREASE(c));
        for (const cipher of nonGreaseCiphers) {
            expect(CIPHER_SUITES[cipher], `Missing cipher suite 0x${cipher.toString(16)}`).to.be.a('string');
        }
    });

    it("can resolve all extension IDs from a Chrome ClientHello", async () => {
        const incomingData = fs.createReadStream(path.join(__dirname, 'fixtures', 'chrome-tls-connect.bin'));
        const clientHello = await readTlsClientHello(incomingData);

        const nonGreaseExts = clientHello.extensions.filter(e => !isGREASE(e.id));
        for (const ext of nonGreaseExts) {
            expect(EXTENSIONS[ext.id], `Missing extension ${ext.id}`).to.be.a('string');
        }
    });
});

describe("getExtensionData", () => {

    it("retrieves SNI from a Chrome ClientHello", async () => {
        const incomingData = fs.createReadStream(path.join(__dirname, 'fixtures', 'chrome-tls-connect.bin'));
        const clientHello = await readTlsClientHello(incomingData);

        const sni = getExtensionData(clientHello.extensions, 0x0000) as { serverName: string };
        expect(sni.serverName).to.equal('localhost');
    });

    it("retrieves ALPN from a Chrome ClientHello", async () => {
        const incomingData = fs.createReadStream(path.join(__dirname, 'fixtures', 'chrome-tls-connect.bin'));
        const clientHello = await readTlsClientHello(incomingData);

        const alpn = getExtensionData(clientHello.extensions, 0x0010) as { protocols: string[] };
        expect(alpn.protocols).to.deep.equal(['h2', 'http/1.1']);
    });

    it("returns null for absent extensions", async () => {
        const incomingData = fs.createReadStream(path.join(__dirname, 'fixtures', 'chrome-tls-connect.bin'));
        const clientHello = await readTlsClientHello(incomingData);

        // heartbeat is not present in the Chrome fixture
        expect(getExtensionData(clientHello.extensions, 0x000F)).to.equal(null);
    });

    let server: net.Server & { destroy?: () => Promise<void> };
    afterEach(() => server?.destroy?.().catch(() => {}));

    it("returns null for SNI/ALPN when not present", async () => {
        const netServer = makeDestroyable(new net.Server());
        server = netServer;

        netServer.listen();
        await new Promise((resolve) => netServer.on('listening', resolve));

        let incomingSocketPromise = getDeferred<net.Socket>();
        netServer.on('connection', (socket) => incomingSocketPromise.resolve(socket));

        const port = (netServer.address() as net.AddressInfo).port;
        tls.connect({ host: 'localhost', port }).on('error', () => {});

        const incomingSocket = await incomingSocketPromise;
        const clientHello = await readTlsClientHello(incomingSocket);

        // Pure TLS connection without SNI or ALPN
        expect(getExtensionData(clientHello.extensions, 0x0000)).to.equal(null);
        expect(getExtensionData(clientHello.extensions, 0x0010)).to.equal(null);
    });
});
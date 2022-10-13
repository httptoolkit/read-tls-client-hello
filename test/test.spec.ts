import * as net from 'net';
import * as tls from 'tls';
import * as https from 'https';
import { makeDestroyable, DestroyableServer } from 'destroyable-server';

import { expect } from 'chai';
import { getDeferred, streamToBuffer } from './test-util';

import {
    getTlsFingerprintData,
    getTlsFingerprintAsJa3
} from '../src/index';

const nodeMajorVersion = parseInt(process.version.slice(1).split('.')[0], 10);

describe("Read-TLS-Fingerprint", () => {

    let server: DestroyableServer<net.Server>;

    afterEach(() => server?.destroy());

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
        const fingerprint = await getTlsFingerprintData(incomingSocket);

        const [
            tlsVersion,
            ciphers,
            extension,
            groups,
            curveFormats
        ] = fingerprint;

        expect(tlsVersion).to.equal(771); // TLS 1.2 - now set even for TLS 1.3 for backward compat
        expect(ciphers.slice(0, 3)).to.deep.equal([4866, 4867, 4865]);
        expect(extension).to.deep.equal([
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
        expect(curveFormats).to.deep.equal([0, 1, 2]);
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
            '0cce74b0d9b7f8528fb2181588d23793' // Node 17+
        ]);
    });

    it("calculates the same fingerprint as ja3.zone", async () => {
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
        const ourFingerprint = await getTlsFingerprintAsJa3(incomingSocket);

        const remoteFingerprint = await new Promise((resolve, reject) => {
            const response = https.get('https://check.ja3.zone/');
            response.on('response', async (resp) => {
                if (resp.statusCode !== 200) reject(new Error(`Unexpected ${resp.statusCode} from ja3.zon`));

                try {
                    const rawData = await streamToBuffer(resp);
                    const data = JSON.parse(rawData.toString());
                    resolve(data.hash);
                } catch (e) {
                    reject(e);
                }
            });
            response.on('error', reject);
        });

        expect(ourFingerprint).to.equal(remoteFingerprint);
    });

});
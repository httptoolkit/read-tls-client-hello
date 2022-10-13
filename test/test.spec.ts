import * as net from 'net';
import * as tls from 'tls';
import { makeDestroyable, DestroyableServer } from 'destroyable-server';

import { expect } from 'chai';
import { getDeferred } from './test-util';

import { getTlsFingerprint } from '../src/index';

const nodeMajorVersion = parseInt(process.version.slice(1).split('.')[0], 10);

describe("Read-TLS-Fingerprint", () => {

    let server: DestroyableServer<net.Server>;

    afterEach(() => server?.destroy());

    it("can read Node's fingerprint", async () => {
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
        const fingerprint = await getTlsFingerprint(incomingSocket);

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
});
import * as net from 'net';
import * as tls from 'tls';
import { makeDestroyable, DestroyableServer } from 'destroyable-server';

import { getDeferred } from './test-util';

import { getTlsFingerprint } from '../src/index';
import { expect } from 'chai';

describe("Read-TLS-Fingerprint", () => {

    let server: DestroyableServer<net.Server>;

    afterEach(() => server?.destroy());

    it("can read Node's fingerprint", async () => {
        server = makeDestroyable(new net.Server());

        server.listen();
        await new Promise((resolve) => server.on('listening', resolve));

        let incomingSocketPromise = getDeferred<net.Socket>();
        server.on('connection', (socket) => incomingSocketPromise.resolve(socket));

        console.log(server.address());
        const port = (server.address() as net.AddressInfo).port;
        tls.connect({
            host: '127.0.0.1',
            port
        }).on('error', () => {}); // Socket will fail, since server never responds, that's OK

        const incomingSocket = await incomingSocketPromise;
        const fingerprint = await getTlsFingerprint(incomingSocket);

        expect(fingerprint).to.equal('22'); // Basic WIP test: yes, this is TLS
    });
});
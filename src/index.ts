import * as stream from 'stream';
import * as crypto from 'crypto';
import * as tls from 'tls';
import * as net from 'net';

import { extensionParsers } from './extension-parsers';
import type { ExtensionDataMap } from './extension-parsers';
import { EXTENSION_IDS } from './lookup-tables';
import type { ExtensionName } from './lookup-tables';

export { extensionParsers } from './extension-parsers';
export type { ExtensionDataMap } from './extension-parsers';
export * from './lookup-tables';

type ErrorWithConsumedData = Error & {
    consumedData: Buffer
};

const collectBytes = (stream: stream.Readable, byteLength: number) => {
    if (byteLength === 0) return Buffer.from([]);

    return new Promise<Buffer>(async (resolve, reject) => {
        const closeReject = () => reject(new Error('Stream closed before expected data could be read'));

        const data: Buffer[] = [];

        try {
            stream.on('error', reject);
            stream.on('close', closeReject);
            let dataLength = 0;
            let readNull = false;
            do {
                if (!stream.readable || readNull) await new Promise<Buffer>((resolve) => stream.once('readable', resolve));

                const nextData = stream.read(byteLength - dataLength)
                    ?? stream.read(); // If less than wanted data is available, at least read what we can get

                if (nextData === null) {
                    // Still null => tried to read, not enough data
                    readNull = true;
                    continue;
                }

                data.push(nextData);
                dataLength += nextData.byteLength;
            } while (dataLength < byteLength)

            return resolve(Buffer.concat(data, byteLength));
        } catch (e) {
            Object.assign(e as ErrorWithConsumedData, { consumedData: data });
            reject(e);
        } finally {
            stream.removeListener('error', reject);
            stream.removeListener('close', closeReject);
        }
    });
};

// https://datatracker.ietf.org/doc/html/draft-davidben-tls-grease-01 defines GREASE values for various
// TLS fields, reserving 0a0a, 1a1a, 2a2a, etc for ciphers, extension ids & supported groups.
export const isGREASE = (value: number) => (value & 0x0f0f) == 0x0a0a;

export type TlsExtension = {
    id: number;
    data: Record<string, unknown> | null;
};

export type TlsClientHelloMessage = {
    version: number;
    random: Buffer;
    sessionId: Buffer;
    cipherSuites: number[];
    compressionMethods: number[];
    extensions: TlsExtension[];
};

// Resolve an ExtensionName (string) to the numeric key in extensionParsers
type ResolveExtensionId<N extends ExtensionName> = (typeof EXTENSION_IDS)[N] & keyof ExtensionDataMap;

// Per-extension typed overloads: known numeric ID or string name → specific return type
export function getExtensionData<K extends keyof ExtensionDataMap>(
    clientHello: TlsClientHelloMessage, id: K
): ExtensionDataMap[K] | null | undefined;
export function getExtensionData<N extends ExtensionName>(
    clientHello: TlsClientHelloMessage, id: N
): ExtensionDataMap[ResolveExtensionId<N>] | null | undefined;
export function getExtensionData(
    clientHello: TlsClientHelloMessage, id: number
): Record<string, unknown> | null | undefined;
export function getExtensionData(clientHello: TlsClientHelloMessage, id: number | ExtensionName) {
    const numId = typeof id === 'string'
        ? EXTENSION_IDS[id]
        : id;
    return clientHello.extensions.find(e => e.id === numId)?.data;
}

/**
 * Separate error class. If you want to detect TLS parsing errors, but ignore TLS fingerprint
 * issues from definitely-not-TLS traffic, you can ignore all instances of this error.
 */
export class NonTlsError extends Error {
    constructor(message: string) {
        super(message);

        // Fix prototypes (required for custom error types):
        const actualProto = new.target.prototype;
        Object.setPrototypeOf(this, actualProto);
    }
}

async function extractTlsHello(inputStream: stream.Readable): Promise<Buffer> {
    const consumedData = [];
    try {
        consumedData.push(await collectBytes(inputStream, 1));
        const [recordType] = consumedData[0];
        if (recordType !== 0x16) throw new Error("Can't calculate TLS fingerprint - not a TLS stream");

        consumedData.push(await collectBytes(inputStream, 2));
        const recordLengthBytes = await collectBytes(inputStream, 2);
        consumedData.push(recordLengthBytes);
        const recordLength = recordLengthBytes.readUInt16BE(0);

        consumedData.push(await collectBytes(inputStream, recordLength));

        // Put all the bytes back, so that this stream can still be used to create a real TLS session
        return Buffer.concat(consumedData);
    } catch (error: any) {
        if (error.consumedData) {
            // This happens if there's an error inside collectBytes with a partial read.
            (error.consumedData as ErrorWithConsumedData).consumedData = Buffer.concat([
                ...consumedData,
                error.consumedData as Buffer
            ])
        } else {
            Object.assign(error, { consumedData: Buffer.concat(consumedData) });
        }

        throw error;
    }
}

export async function readTlsClientHello(inputStream: stream.Readable): Promise<TlsClientHelloMessage> {
    const wasFlowing = inputStream.readableFlowing;
    if (wasFlowing) inputStream.pause(); // Pause other readers, so we have time to precisely get the data we need.

    let clientHelloRecordData: Buffer;
    try {
        clientHelloRecordData = await extractTlsHello(inputStream);
    } catch (error: any) {
        if ('consumedData' in error) {
            inputStream.unshift(error.consumedData as Buffer);
        }
        if (wasFlowing) inputStream.resume(); // If there were other readers, resume and let them continue
        throw new NonTlsError(error.message);
    }

    // Put all the bytes back, so that this stream can still be used to create a real TLS session
    inputStream.unshift(clientHelloRecordData);
    if (wasFlowing) inputStream.resume(); // If there were other readers, resume and let them continue

    // Collect all the hello bytes, and then give us a stream of exactly only those bytes, so we can
    // still process them step by step in order:
    const clientHello = clientHelloRecordData.slice(5); // Strip TLS record prefix
    const helloDataStream = stream.Readable.from(clientHello, { objectMode: false });

    const [helloType] = (await collectBytes(helloDataStream, 1));
    if (helloType !== 0x1) throw new Error("Can't calculate TLS fingerprint - not a TLS client hello");

    const helloLength = (await collectBytes(helloDataStream, 3)).readIntBE(0, 3);
    if (helloLength !== clientHello.byteLength - 4) throw new Error(
        `Unexpected client hello length: ${helloLength} (of ${clientHello.byteLength})`
    );

    const clientTlsVersion = await collectBytes(helloDataStream, 2);
    const clientRandom = await collectBytes(helloDataStream, 32);

    const [sessionIdLength] = await collectBytes(helloDataStream, 1);
    const sessionId = await collectBytes(helloDataStream, sessionIdLength);

    const cipherSuitesLength = (await collectBytes(helloDataStream, 2)).readUInt16BE(0);
    const cipherSuites = await collectBytes(helloDataStream, cipherSuitesLength);

    const [compressionMethodsLength] = await collectBytes(helloDataStream, 1);
    const compressionMethods = await collectBytes(helloDataStream, compressionMethodsLength);

    const allCipherSuiteIds: number[] = [];
    for (let i = 0; i < cipherSuites.length; i += 2) {
        allCipherSuiteIds.push(cipherSuites.readUInt16BE(i));
    }

    const allCompressionMethods: number[] = Array.from(compressionMethods);

    const extensionsLength = (await collectBytes(helloDataStream, 2)).readUInt16BE(0);
    let readExtensionsDataLength = 0;
    const parsedExtensions: TlsExtension[] = [];

    while (readExtensionsDataLength < extensionsLength) {
        const extensionId = (await collectBytes(helloDataStream, 2)).readUInt16BE(0);
        const extensionLength = (await collectBytes(helloDataStream, 2)).readUInt16BE(0);
        const extensionData = await collectBytes(helloDataStream, extensionLength);

        let parsedData: Record<string, unknown> | null = null;
        const parser = (extensionParsers as Record<number, ((data: Buffer) => Record<string, unknown> | null) | undefined>)[extensionId];
        if (parser && !isGREASE(extensionId)) {
            try {
                parsedData = parser(extensionData);
            } catch {
                parsedData = null; // Malformed extension data - fall back gracefully
            }
        }

        parsedExtensions.push({ id: extensionId, data: parsedData });
        readExtensionsDataLength += 4 + extensionLength;
    }

    return {
        version: clientTlsVersion.readUInt16BE(0),
        random: clientRandom,
        sessionId,
        cipherSuites: allCipherSuiteIds,
        compressionMethods: allCompressionMethods,
        extensions: parsedExtensions
    };
}

export function calculateJa3(clientHello: TlsClientHelloMessage) {
    const ciphers = clientHello.cipherSuites.filter(id => !isGREASE(id));
    const extensionIds = clientHello.extensions.map(e => e.id).filter(id => !isGREASE(id));

    const groups = getExtensionData(clientHello, 0x000A)
        ?.groups.filter(id => !isGREASE(id)) ?? [];

    const curveFormats = getExtensionData(clientHello, 0x000B)
        ?.formats ?? [];

    const fingerprintString = [
        clientHello.version,
        ciphers.join('-'),
        extensionIds.join('-'),
        groups.join('-'),
        curveFormats.join('-')
    ].join(',');

    return crypto.createHash('md5').update(fingerprintString).digest('hex');
}

export async function getTlsFingerprintAsJa3(rawStream: stream.Readable) {
    return calculateJa3(await readTlsClientHello(rawStream));
}

export function calculateJa4(clientHello: TlsClientHelloMessage): string {
    const ciphers = clientHello.cipherSuites.filter(id => !isGREASE(id));
    const extensionIds = clientHello.extensions.map(e => e.id).filter(id => !isGREASE(id));

    const serverName = getExtensionData(clientHello, 0x0000)?.serverName;
    const alpnProtocols = getExtensionData(clientHello, 0x0010)?.protocols;
    const sigAlgorithms = getExtensionData(clientHello, 0x000D)?.algorithms ?? [];

    // Part A: Protocol info
    const protocol = 't'; // We only handle TCP for now

    const version = extensionIds.includes(0x002B)
        ? '13' // TLS 1.3 uses the supported versions extension, and 1.4+ doesn't exist (yet)
        : { // Previous TLS sets the version in the handshake up front:
            0x0303: '12',
            0x0302: '11',
            0x0301: '10'
        }[clientHello.version]
        ?? '00'; // Other unknown version

    const sni = !serverName ? 'i' : 'd'; // 'i' for IP (no SNI), 'd' for domain

    // Handle different ALPN protocols
    let alpn = '00';
    const firstProtocol = alpnProtocols?.[0];
    if (firstProtocol && firstProtocol.length >= 1) {
        // Take first and last character of the protocol string
        alpn = firstProtocol.length >= 2
            ? `${firstProtocol[0]}${firstProtocol[firstProtocol.length - 1]}`
            : `${firstProtocol[0]}${firstProtocol[0]}`;
    }

    // Format numbers as fixed-width hex
    const cipherCount = ciphers.length.toString().padStart(2, '0');
    const extensionCount = extensionIds.length.toString().padStart(2, '0');

    const ja4_a = `${protocol}${version}${sni}${cipherCount}${extensionCount}${alpn}`;

    // Part B: Truncated SHA256 of cipher suites
    const cipherHexValues = ciphers
        .map(c => c.toString(16).padStart(4, '0'));
    const sortedCiphers = [...cipherHexValues].sort().join(',');
    const cipherHash = ciphers.length
        ? crypto.createHash('sha256')
            .update(sortedCiphers)
            .digest('hex')
            .slice(0, 12)
        : '000000000000'; // No ciphers provided

    // Part C: Truncated SHA256 of extensions + sig algorithms
    // Get extensions (excluding SNI and ALPN)
    const extensionsStr = extensionIds
        .filter(e => e !== 0x0 && e !== 0x10)
        .sort((a, b) => a - b)
        .map(e => e.toString(16).padStart(4, '0'))
        .join(',');

    const signatureAlgorithmsStr = sigAlgorithms
        .filter(s => !isGREASE(s))
        .map(s => s.toString(16).padStart(4, '0'))
        .join(',');

    // Add separator only if we have signature algorithms
    const separator = signatureAlgorithmsStr ? '_' : '';

    // Combine and hash
    const ja4_c_raw = `${extensionsStr}${separator}${signatureAlgorithmsStr}`;

    const extensionHash = crypto.createHash('sha256')
        .update(ja4_c_raw)
        .digest('hex')
        .slice(0, 12);

    return `${ja4_a}_${cipherHash}_${extensionHash}`;
}

export async function getTlsFingerprintAsJa4(rawStream: stream.Readable) {
    return calculateJa4(await readTlsClientHello(rawStream));
}

interface SocketWithHello extends net.Socket {
    tlsClientHello?: TlsClientHelloMessage & {
        ja3: string;
        ja4: string;
    }
}

declare module 'tls' {
    interface TLSSocket {
        /**
         * This module extends the global TLS types so that all TLS sockets may include
         * TLS fingerprint data.
         *
         * This is only set if the socket came from a TLS server where fingerprinting
         * has been enabled with `trackClientHellos`.
         */
        tlsClientHello?: TlsClientHelloMessage & {
            ja3: string;
            ja4: string;
        }
    }
}

/**
 * Modify a TLS server, so that the TLS client hello is always parsed and the result is
 * attached to all sockets at the point when the 'secureConnection' event fires.
 *
 * This method mutates and returns the TLS server provided. TLS client hello data is
 * available from all TLS sockets afterwards in the `socket.tlsClientHello` property.
 *
 * This will work for all standard uses of a TLS server or similar (e.g. an HTTPS server)
 * but may behave unpredictably for advanced use cases, e.g. if you are already
 * manually injecting connections, hooking methods or events or otherwise doing something
 * funky & complicated. In those cases you probably want to use the fingerprint
 * calculation methods directly inside your funky logic instead.
 */
export function trackClientHellos(tlsServer: tls.Server) {
    // Disable the normal TLS 'connection' event listener that triggers TLS setup:
    const tlsConnectionListener = tlsServer.listeners('connection')[0] as (socket: net.Socket) => {};
    if (!tlsConnectionListener) throw new Error('TLS server is not listening for connection events');
    tlsServer.removeListener('connection', tlsConnectionListener);

    // Listen ourselves for connections, get the fingerprint first, then let TLS setup resume:
    tlsServer.on('connection', async (socket: SocketWithHello) => {
        try {
            const clientHello = await readTlsClientHello(socket);

            socket.tlsClientHello = {
                ...clientHello,
                ja3: calculateJa3(clientHello),
                ja4: calculateJa4(clientHello)
            };
        } catch (e) {
            if (!(e instanceof NonTlsError)) { // Ignore totally non-TLS traffic
                console.warn(`TLS client hello data not available for TLS connection from ${
                    socket.remoteAddress ?? 'unknown address'
                }: ${(e as Error).message ?? e}`);
            }
        }

        // Once we have a fingerprint, TLS handshakes can continue as normal:
        tlsConnectionListener.call(tlsServer, socket);
    });

    tlsServer.prependListener('secureConnection', (tlsSocket: tls.TLSSocket) => {
        const fingerprint = (tlsSocket as unknown as {
            _parent?: SocketWithHello, // Private TLS socket field which points to the source
        })._parent?.tlsClientHello;

        tlsSocket.tlsClientHello = fingerprint;
    });

    return tlsServer;
}
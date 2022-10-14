import * as stream from 'stream';
import * as crypto from 'crypto';

const collectBytes = (stream: stream.Readable, byteLength: number) => {
    if (byteLength === 0) return Buffer.from([]);

    return new Promise<Buffer>(async (resolve, reject) => {
        const closeReject = () => reject(new Error('Stream closed before expected data could be read'));

        try {
            stream.on('error', reject);
            stream.on('close', closeReject);

            const data: Buffer[] = [];
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
            reject(e);
        } finally {
            stream.removeListener('error', reject);
            stream.removeListener('close', closeReject);
        }
    });
};

const getUint16BE = (buffer: Buffer, offset: number) =>
    (buffer[offset] << 8) + buffer[offset+1];

// https://datatracker.ietf.org/doc/html/draft-davidben-tls-grease-01 defines GREASE values for various
// TLS fields, reserving 0a0a, 1a1a, 2a2a, etc for ciphers, extension ids & supported groups.
const isGREASE = (value: number) => (value & 0x0f0f) == 0x0a0a;

export type TlsFingerprintData = [
    tlsVersion: number,
    ciphers: number[],
    extensions: number[],
    groups: number[],
    curveFormats: number[]
];

export async function getTlsFingerprintData(rawStream: stream.Readable): Promise<TlsFingerprintData> {
    // Create a separate stream, which isn't flowing, so we can read byte-by-byte regardless of how else
    // the stream is being used.
    const inputStream = new stream.PassThrough();
    rawStream.pipe(inputStream);

    const [recordType] = await collectBytes(inputStream, 1);
    if (recordType !== 0x16) throw new Error("Can't calculate TLS fingerprint - not a TLS stream");

    const tlsRecordVersion = await collectBytes(inputStream, 2);
    const recordLength = (await collectBytes(inputStream, 2)).readUint16BE();

    // Collect all the hello bytes, and then give us a stream of exactly only those bytes, so we can
    // still process them step by step in order:
    const helloDataStream = stream.Readable.from(await collectBytes(inputStream, recordLength), { objectMode: false });
    rawStream.unpipe(inputStream); // Don't need any more data now, thanks.

    const [helloType] = (await collectBytes(helloDataStream, 1));
    if (helloType !== 0x1) throw new Error("Can't calculate TLS fingerprint - not a TLS client hello");

    const helloLength = (await collectBytes(helloDataStream, 3)).readIntBE(0, 3);
    if (helloLength !== recordLength - 4) throw new Error(
        `Unexpected client hello length: ${helloLength} (or ${recordLength})`
    );

    const clientTlsVersion = await collectBytes(helloDataStream, 2);
    const clientRandom = await collectBytes(helloDataStream, 32);

    const [sessionIdLength] = await collectBytes(helloDataStream, 1);
    const sessionId = await collectBytes(helloDataStream, sessionIdLength);

    const cipherSuitesLength = (await collectBytes(helloDataStream, 2)).readUint16BE();
    const cipherSuites = await collectBytes(helloDataStream, cipherSuitesLength);

    const [compressionMethodsLength] = await collectBytes(helloDataStream, 1);
    const compressionMethods = await collectBytes(helloDataStream, compressionMethodsLength);

    const extensionsLength = (await collectBytes(helloDataStream, 2)).readUint16BE();
    let readExtensionsDataLength = 0;
    const extensions: Array<{ id: Buffer, data: Buffer }> = [];

    while (readExtensionsDataLength < extensionsLength) {
        const extensionId = await collectBytes(helloDataStream, 2);
        const extensionLength = (await collectBytes(helloDataStream, 2)).readUint16BE();
        const extensionData = await collectBytes(helloDataStream, extensionLength);

        extensions.push({ id: extensionId, data: extensionData });
        readExtensionsDataLength += 4 + extensionLength;
    }

    // All data parsed! Now turn it into the fingerprint format:
    //SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat

    const tlsVersionFingerprint = clientTlsVersion.readUint16BE()

    const cipherFingerprint: number[] = [];
    for (let i = 0; i < cipherSuites.length; i += 2) {
        const cipherId = getUint16BE(cipherSuites, i);
        if (isGREASE(cipherId)) continue;
        cipherFingerprint.push(cipherId);
    }

    const extensionsFingerprint: number[] = extensions
        .map(({ id }) => getUint16BE(id, 0))
        .filter(id => !isGREASE(id));

    const supportedGroupsData = (
        extensions.find(({ id }) => id.equals(Buffer.from([0x0, 0x0a])))?.data
        ?? Buffer.from([])
    ).slice(2) // Drop the length prefix

    const groupsFingerprint: number[] = [];
    for (let i = 0; i < supportedGroupsData.length; i += 2) {
        const groupId = getUint16BE(supportedGroupsData, i)
        if (isGREASE(groupId)) continue;
        groupsFingerprint.push(groupId);
    }

    const curveFormatsData = extensions.find(({ id }) => id.equals(Buffer.from([0x0, 0x0b])))?.data
        ?? Buffer.from([]);
    const curveFormatsFingerprint: number[] = Array.from(curveFormatsData.slice(1)); // Drop length prefix

    return [
        tlsVersionFingerprint,
        cipherFingerprint,
        extensionsFingerprint,
        groupsFingerprint,
        curveFormatsFingerprint
    ];
}

export function calculateJa3FromFingerprintData(fingerprintData: TlsFingerprintData) {
    const fingerprintString = [
        fingerprintData[0],
        fingerprintData[1].join('-'),
        fingerprintData[2].join('-'),
        fingerprintData[3].join('-'),
        fingerprintData[4].join('-')
    ].join(',');

    return crypto.createHash('md5').update(fingerprintString).digest('hex');
}

export async function getTlsFingerprintAsJa3(rawStream: stream.Readable) {
    return calculateJa3FromFingerprintData(await getTlsFingerprintData(rawStream));
}
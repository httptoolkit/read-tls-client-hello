import * as stream from "stream";

export async function getTlsFingerprint(data: stream.Readable) {
    const firstData: any = await new Promise((resolve) => data.on('data', resolve));
    return firstData[0].toString();
}
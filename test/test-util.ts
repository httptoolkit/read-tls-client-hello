import * as fs from 'fs';

export const testKey = fs.readFileSync(__dirname + '/fixtures/server.key');
export const testCert = fs.readFileSync(__dirname + '/fixtures/server.crt');

export type Deferred<T> = Promise<T> & {
    resolve(value: T): void,
    reject(e: Error): void
}

export function getDeferred<T>(): Deferred<T> {
    let resolveCallback: (value: T) => void;
    let rejectCallback: (e: Error) => void;
    let result = <Deferred<T>> new Promise((resolve, reject) => {
        resolveCallback = resolve;
        rejectCallback = reject;
    });
    result.resolve = resolveCallback!;
    result.reject = rejectCallback!;

    return result;
}
// Extension-specific parsers for TLS ClientHello extensions.
// Each parser takes the raw extension data buffer and returns a structured object,
// or null if the extension format is unknown/unparseable.
//
// Return type annotations are intentionally omitted so that TypeScript infers the
// specific shape of each parser's return value. This powers the per-extension
// return types on getExtensionData().

// --- Parsers for extensions already extracted in the main module ---

export function parseSniExtension(data: Buffer) {
    // SNI list: 2-byte total length, then entries of [1-byte type, 2-byte name length, name]
    let offset = 0;
    while (offset < data.byteLength) {
        const entryLength = data.readUInt16BE(offset);
        offset += 2;
        const entryType = data[offset];
        offset += 1;
        const nameLength = data.readUInt16BE(offset);
        offset += 2;

        if (nameLength !== entryLength - 3) {
            return null;
        }

        const name = data.slice(offset, offset + nameLength).toString('ascii');
        offset += nameLength;

        if (entryType === 0x0) return { serverName: name };
    }

    return { serverName: undefined as string | undefined };
}

export function parseSupportedGroupsExtension(data: Buffer) {
    const listLength = data.readUInt16BE(0);
    const groups: number[] = [];
    for (let i = 2; i < listLength + 2; i += 2) {
        groups.push(data.readUInt16BE(i));
    }
    return { groups };
}

export function parseEcPointFormatsExtension(data: Buffer) {
    const length = data[0];
    const formats: number[] = [];
    for (let i = 1; i <= length; i++) {
        formats.push(data[i]);
    }
    return { formats };
}

export function parseSignatureAlgorithmsExtension(data: Buffer) {
    const listLength = data.readUInt16BE(0);
    const algorithms: number[] = [];
    for (let i = 2; i < listLength + 2; i += 2) {
        algorithms.push(data.readUInt16BE(i));
    }
    return { algorithms };
}

export function parseAlpnExtension(data: Buffer) {
    const protocols: string[] = [];
    const listLength = data.readUInt16BE(0);
    if (listLength !== data.byteLength - 2) return { protocols };

    let offset = 2;
    while (offset < data.byteLength) {
        const nameLength = data[offset];
        offset += 1;
        const name = data.slice(offset, offset + nameLength).toString('ascii');
        offset += nameLength;
        protocols.push(name);
    }
    return { protocols };
}

// --- New extension parsers ---

export function parseMaxFragmentLengthExtension(data: Buffer) {
    return { maxFragmentLength: data[0] };
}

export function parseStatusRequestExtension(data: Buffer) {
    return { statusType: data[0] };
}

export function parseStatusRequestV2Extension(data: Buffer) {
    const statusTypes: number[] = [];
    const totalLength = data.readUInt16BE(0);
    let offset = 2;
    const end = 2 + totalLength;
    while (offset < end) {
        const type = data[offset];
        offset += 1;
        const itemLength = data.readUInt16BE(offset);
        offset += 2;
        offset += itemLength; // skip data bytes
        statusTypes.push(type);
    }
    return { statusTypes };
}

export function parsePaddingExtension(data: Buffer) {
    return { paddingLength: data.byteLength };
}

export function parseCompressCertificateExtension(data: Buffer) {
    const length = data[0];
    const algorithms: number[] = [];
    for (let i = 1; i < 1 + length; i += 2) {
        algorithms.push(data.readUInt16BE(i));
    }
    return { algorithms };
}

export function parseRecordSizeLimitExtension(data: Buffer) {
    return { recordSizeLimit: data.readUInt16BE(0) };
}

export function parseSessionTicketExtension(data: Buffer) {
    return { ticketLength: data.byteLength };
}

export function parsePreSharedKeyExtension(data: Buffer) {
    const identities: Array<{ identityLength: number; obfuscatedTicketAge: number }> = [];
    const identitiesLength = data.readUInt16BE(0);
    let offset = 2;
    const identitiesEnd = 2 + identitiesLength;
    while (offset < identitiesEnd) {
        const identityLength = data.readUInt16BE(offset);
        offset += 2;
        offset += identityLength; // skip identity bytes
        const obfuscatedTicketAge = data.readUInt32BE(offset);
        offset += 4;
        identities.push({ identityLength, obfuscatedTicketAge });
    }
    // Skip binders section entirely
    return { identities };
}

export function parseSupportedVersionsExtension(data: Buffer) {
    const length = data[0];
    const versions: number[] = [];
    for (let i = 1; i < 1 + length; i += 2) {
        versions.push(data.readUInt16BE(i));
    }
    return { versions };
}

export function parseCookieExtension(data: Buffer) {
    const cookieLength = data.readUInt16BE(0);
    return { cookieLength };
}

export function parsePskKeyExchangeModesExtension(data: Buffer) {
    const length = data[0];
    const modes: number[] = [];
    for (let i = 1; i <= length; i++) {
        modes.push(data[i]);
    }
    return { modes };
}

export function parseSignatureAlgorithmsCertExtension(data: Buffer) {
    // Same format as signature_algorithms
    return parseSignatureAlgorithmsExtension(data);
}

export function parseKeyShareExtension(data: Buffer) {
    const entries: Array<{ group: number; keyExchangeLength: number }> = [];
    const totalLength = data.readUInt16BE(0);
    let offset = 2;
    const end = 2 + totalLength;
    while (offset < end) {
        const group = data.readUInt16BE(offset);
        offset += 2;
        const keyExchangeLength = data.readUInt16BE(offset);
        offset += 2;
        offset += keyExchangeLength; // skip key exchange data
        entries.push({ group, keyExchangeLength });
    }
    return { entries };
}

export function parseRenegotiationInfoExtension(data: Buffer) {
    const renegotiatedConnectionLength = data[0];
    return { renegotiatedConnectionLength };
}

export function parseHeartbeatExtension(data: Buffer) {
    return { mode: data[0] };
}

export function parseEncryptedClientHelloExtension(data: Buffer) {
    const type = data[0];
    if (type === 1) {
        // Inner: empty after type byte
        return { type };
    }
    // Outer
    let offset = 1;
    const kdfId = data.readUInt16BE(offset); offset += 2;
    const aeadId = data.readUInt16BE(offset); offset += 2;
    const configId = data[offset]; offset += 1;
    const encLength = data.readUInt16BE(offset); offset += 2;
    offset += encLength; // skip enc bytes
    const payloadLength = data.readUInt16BE(offset);
    return { type, kdfId, aeadId, configId, encLength, payloadLength };
}

export function parseApplicationSettingsExtension(data: Buffer) {
    // Same format as ALPN
    return parseAlpnExtension(data);
}

// Flag extension parser - returns empty object for extensions whose presence is the signal
function flagExtension() {
    return {} as Record<string, never>;
}

// Map of extension ID to parser function. Uses `as const satisfies` so that
// TypeScript preserves the per-parser return types for each numeric key.
export const extensionParsers = {
    0x0000: parseSniExtension,
    0x0001: parseMaxFragmentLengthExtension,
    0x0005: parseStatusRequestExtension,
    0x000A: parseSupportedGroupsExtension,
    0x000B: parseEcPointFormatsExtension,
    0x000D: parseSignatureAlgorithmsExtension,
    0x000F: parseHeartbeatExtension,
    0x0010: parseAlpnExtension,
    0x0011: parseStatusRequestV2Extension,
    0x0012: flagExtension,  // signed_certificate_timestamp
    0x0015: parsePaddingExtension,
    0x0016: flagExtension,  // encrypt_then_mac
    0x0017: flagExtension,  // extended_master_secret
    0x001B: parseCompressCertificateExtension,
    0x001C: parseRecordSizeLimitExtension,
    0x0023: parseSessionTicketExtension,
    0x0029: parsePreSharedKeyExtension,
    0x002A: flagExtension,  // early_data
    0x002B: parseSupportedVersionsExtension,
    0x002C: parseCookieExtension,
    0x002D: parsePskKeyExchangeModesExtension,
    0x0031: flagExtension,  // post_handshake_auth
    0x0032: parseSignatureAlgorithmsCertExtension,
    0x0033: parseKeyShareExtension,
    0x4469: parseApplicationSettingsExtension,  // ALPS
    0xFE0D: parseEncryptedClientHelloExtension, // ECH
    0xFF01: parseRenegotiationInfoExtension,
} as const satisfies Record<number, (data: Buffer) => Record<string, unknown> | null>;

// Per-extension return type map, inferred from the parser functions above.
// ExtensionDataMap[0x0033] = { entries: Array<{ group: number; keyExchangeLength: number }> }
type Parsers = typeof extensionParsers;
export type ExtensionDataMap = {
    [K in keyof Parsers]: NonNullable<ReturnType<Parsers[K]>>
};

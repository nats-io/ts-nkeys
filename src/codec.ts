/*
 * Copyright 2018 The NATS Authors
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {crc16} from "./crc16";
import ed25519 = require('tweetnacl');
import {NKeysError, NKeysErrorCode, Prefix, Prefixes} from "./nkeys";
import * as util from "./util";
import {base32} from "./base32";


export interface SeedDecode {
    prefix: Prefix;
    buf: Buffer;
}

export class Codec {
    static toArrayBuffer: util.ToArrayBuffer = util.toArrayBuffer();

    static encode(prefix: Prefix, src: Buffer): Buffer {
        if(! Buffer.isBuffer(src)) {
            throw new NKeysError(NKeysErrorCode.SerializationError);
        }

        if (!Prefixes.isValidPrefix(prefix)) {
            throw new NKeysError(NKeysErrorCode.InvalidPrefixByte);
        }

        return Codec._encode(false, prefix, src);
    }

    static encodeSeed(role: Prefix, src: Buffer): Buffer {
        if(! Prefixes.isValidPublicPrefix(role)) {
            throw new NKeysError(NKeysErrorCode.InvalidPrefixByte);
        }
        if(! Buffer.isBuffer(src)) {
            throw new NKeysError(NKeysErrorCode.ApiError);
        }

        if(src.byteLength != ed25519.sign.seedLength) {
            throw new NKeysError(NKeysErrorCode.InvalidSeedLen);
        }
        return Codec._encode(true, role, src);
    }

    static decode(expected: Prefix, src: Buffer): Buffer {
        if(! Prefixes.isValidPrefix(expected)) {
            throw new NKeysError(NKeysErrorCode.InvalidPrefixByte);
        }
        let raw = Codec._decode(src);
        if (raw[0] !== expected) {
            throw new NKeysError(NKeysErrorCode.InvalidPrefixByte);
        }
        return raw.slice(1);
    }

    static decodeSeed(src: Buffer): SeedDecode {
        let raw = Codec._decode(src);
        let prefix = Codec._decodePrefix(raw);
        if (prefix[0] != Prefix.Seed) {
            throw new NKeysError(NKeysErrorCode.InvalidSeed);
        }
        if (!Prefixes.isValidPublicPrefix(prefix[1])) {
            throw new NKeysError(NKeysErrorCode.InvalidPrefixByte);
        }
        return ({buf: raw.slice(2), prefix: prefix[1]})
    }

    // unsafe encode no prefix/role validation
    static _encode(seed: boolean, role: Prefix, payload: Buffer): Buffer {
        // offsets for this token
        let payloadOffset = seed ? 2 : 1;
        let payloadLen = payload.byteLength;
        let checkLen = 2;
        let cap = payloadOffset + payloadLen + checkLen;
        let checkOffset = payloadOffset + payloadLen;

        let raw = Buffer.alloc(cap);
        // make the prefixes human readable when encoded
        if (seed) {
            let encodedPrefix = Codec._encodePrefix(Prefix.Seed, role);
            encodedPrefix.copy(raw,0,0);
        } else {
            raw[0] = role;
        }
        payload.copy(raw, payloadOffset, 0);

        //calculate the checksum write it LE
        let checksum = crc16.checksum(raw.slice(0,checkOffset));
        raw.writeUInt16LE(checksum, checkOffset);

        return base32.encode(raw);
    }

    // unsafe decode - no prefix/role validation
    static _decode(src: Buffer): Buffer {
        if (src.byteLength < 4) {
            throw new NKeysError(NKeysErrorCode.InvalidEncoding);
        }
        let raw: Buffer;
        try {
            raw = base32.decode(src);
        } catch(ex) {
            throw new NKeysError(NKeysErrorCode.InvalidEncoding, ex);
        }

        let checkOffset = raw.byteLength - 2;
        let checksum = raw.readUInt16LE(checkOffset);

        let payload = raw.slice(0, checkOffset);
        if (!crc16.validate(payload, checksum)) {
            throw new NKeysError(NKeysErrorCode.InvalidChecksum);
        }
        return payload;
    }

    static _encodePrefix(kind: Prefix, role: Prefix): Buffer {
        // In order to make this human printable for both bytes, we need to do a little
        // bit manipulation to setup for base32 encoding which takes 5 bits at a time.
        let b1 = kind | (role >> 5);
        let b2 = (role & 31) << 3; // 31 = 00011111
        return Buffer.from([b1, b2]);
    }

    static _decodePrefix(raw: Buffer) : Uint8Array {
        // Need to do the reverse from the printable representation to
        // get back to internal representation.
        let b1 = raw[0] & 248; // 248 = 11111000
        let b2 = (raw[0]&7)<<5 | ((raw[1] & 248) >> 3); // 7 = 00000111
        let a = new Uint8Array(2);
        a[0] = b1;
        a[1] = b2;
        return a;
    }
}

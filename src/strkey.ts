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

import {Prefix, Prefixes} from "./prefix";
import {crc16} from "./crc16";
import b32enc = require('base32-encode');
import b32dec = require('base32-decode');
import {NKeysError, NKeysErrorCode} from "./errors";
import ed25519 = require('tweetnacl')

export class Token {
    raw: Buffer;
    isSeed: boolean;
    prefix: Uint8Array;
    private constructor(str: string, isSeed=true) {
        let t = isSeed ? TokenCodec.decodeSeed(str) : TokenCodec.decode(str);
        if(! Buffer.isBuffer(t)) {
            throw new NKeysError(NKeysErrorCode.SerializationError);
        }
        this.raw = t;
        this.isSeed = isSeed;
        if(isSeed) {
            if (this.raw.byteLength < 4) {
                throw new NKeysError(NKeysErrorCode.InvalidEncoding);
            }
            this.prefix = TokenCodec.decodePrefix(this.raw);
        } else {
            this.prefix = new Uint8Array([this.raw.readUInt8(0)]);
        }
    }

    getPrefix() : Prefix {
        return this.prefix[0];
    }

    getPublic() : Prefix {
        if(!this.isSeed) {
            return -1;
        }
        return this.prefix[1];
    }

    getKey() : Buffer {
        return this.raw.slice(1);
    }

    hasPrefix(prefix: Prefix) : boolean {
        return this.getPrefix() == prefix;
    }

    hasPublicPrefix() : boolean {
        return Prefixes.isValidPublicPrefix(this.getPrefix())
    }

    static decode(str: string, isSeed: boolean) : Token {
        return new Token(str, isSeed);
    }
}

export class TokenCodec {
    static encode(prefix: Prefix, src: Buffer): string | Error {
        if(! Buffer.isBuffer(src)) {
            return new NKeysError(NKeysErrorCode.SerializationError);
        }

        if (!Prefixes.isValidPrefix(prefix)) {
            return new NKeysError(NKeysErrorCode.InvalidPrefixByte);
        }

        // offsets
        let payloadOffset = 1;
        let payloadLen = src.byteLength;
        let checkLen = 2;
        let cap = payloadOffset + payloadLen + checkLen;
        let checkOffset = payloadOffset + payloadLen;

        let raw = new Buffer(cap);
        raw[0] = prefix;
        src.copy(raw, payloadOffset);

        //calculate the checksum write it LE
        let checksum = crc16.checksum(raw.slice(0, checkOffset));
        raw.writeUInt16LE(checksum, checkOffset);

        // generate a string
        return b32enc(raw, 'RFC3548');
    }

    static decode(src: string): Buffer | Error {
        let raw = Buffer.from(b32dec(src, 'RFC3548'));

        let checkOffset = raw.byteLength - 2;
        let checksum = raw.readUInt16LE(checkOffset);

        let payload = raw.slice(0, checkOffset);
        if (!crc16.validate(payload, checksum)) {
            return new NKeysError(NKeysErrorCode.InvalidChecksum);
        }
        return payload;
    }

    static decodeSeed(src: string): Buffer | Error {
        let raw = TokenCodec.decode(src);
        if(raw instanceof Error) {
            return raw;
        }
        let prefix = TokenCodec.decodePrefix(raw);
        if(prefix[0] != Prefix.Seed) {
            return new NKeysError(NKeysErrorCode.InvalidSeed);
        }
        if(! Prefixes.isValidPublicPrefix(prefix[1])) {
            return new NKeysError(NKeysErrorCode.InvalidSeed);
        }
        return raw;
    }


    static decodeAs(expected: Prefix, src: string) : Buffer | Error {
        let t = Token.decode(src, false);
        if(t instanceof Error) {
            return t;
        }
        if(t.getPrefix() != expected) {
            return new NKeysError(NKeysErrorCode.InvalidPrefixByte);
        }
        return t.getKey();
    }

    static encodeSeed(role: Prefix, src: Buffer): string | Error {
        if(! Buffer.isBuffer(src)) {
            return new NKeysError(NKeysErrorCode.SerializationError);
        }
        if(! Prefixes.isValidPublicPrefix(role)) {
            return new NKeysError(NKeysErrorCode.InvalidPrefixByte);
        }
        if(src.byteLength != ed25519.sign.secretKeyLength) {
            return new NKeysError(NKeysErrorCode.InvalidSeedLen);
        }

        // offsets for this token
        let payloadOffset = 2;
        let payloadLen = src.byteLength;
        let checkLen = 2;
        let cap = payloadOffset + payloadLen + checkLen;
        let checkOffset = payloadOffset + payloadLen;

        // make the prefixes human readable when encoded
        let prefix = TokenCodec.encodePrefix(Prefix.Seed, role);

        let raw = new Buffer(cap);
        prefix.copy(raw,0,0);
        src.copy(raw, payloadOffset, 0);

        //calculate the checksum write it LE
        let checksum = crc16.checksum(raw.slice(0,checkOffset));
        raw.writeUInt16LE(checksum, checkOffset);

        // generate a string
        return b32enc(raw, 'RFC3548');
    }

    static encodePrefix(kind: Prefix, role: Prefix): Buffer {
        // In order to make this human printable for both bytes, we need to do a little
        // bit manipulation to setup for base32 encoding which takes 5 bits at a time.
        let b1 = kind | (role >> 5);
        let b2 = (role & 31) << 3; // 31 = 00011111
        return new Buffer([b1, b2]);
    }

    static decodePrefix(raw: Buffer) : Uint8Array {
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


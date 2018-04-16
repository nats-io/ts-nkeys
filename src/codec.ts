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
import b32enc = require('base32-encode');
import b32dec = require('base32-decode');
import ed25519 = require('tweetnacl');
import {NKeysError, NKeysErrorCode, Prefix, Prefixes} from "./nkeys";
import * as util from "./util";


export interface SeedDecode {
    prefix: Prefix;
    buf: Buffer;
}

export class Codec {
    static toArrayBuffer: util.ToArrayBuffer = util.toArrayBuffer();

    static encode(prefix: Prefix, src: Buffer): Promise<string> {
        return new Promise((resolve,reject)=> {
            if(! Buffer.isBuffer(src)) {
                reject(new NKeysError(NKeysErrorCode.SerializationError));
                return;
            }

            if (!Prefixes.isValidPrefix(prefix)) {
                reject(new NKeysError(NKeysErrorCode.InvalidPrefixByte));
                return;
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

            // generate a base32 string - remove the padding
            let str = b32enc(Codec.toArrayBuffer(raw), 'RFC3548');
            str = str.replace(/=+$/, '');
            resolve(str);
        });
    }

    static decode(src: string): Promise<Buffer> {
        return new Promise((resolve,reject)=> {
            if(! Prefixes.startsWithValidPrefix(src)) {
                reject(new NKeysError(NKeysErrorCode.InvalidPrefixByte));
                return;
            }

            let buf: ArrayBuffer;
            try{
                buf = b32dec(src, 'RFC3548');
            }
            catch(ex) {
                reject(new NKeysError(NKeysErrorCode.InvalidEncoding, ex));
                return;
            }

            let raw = Buffer.from(buf);
            if (raw.byteLength < 3) {
                reject(new NKeysError(NKeysErrorCode.InvalidEncoding));
                return;
            }

            let checkOffset = raw.byteLength - 2;
            let checksum = raw.readUInt16LE(checkOffset);

            let payload = raw.slice(0, checkOffset);
            if (!crc16.validate(payload, checksum)) {
                reject(new NKeysError(NKeysErrorCode.InvalidChecksum));
                return;
            }
            resolve(payload);
        });
    }

    static decodeExpectingPrefix(expected: Prefix, src: string): Promise<Buffer> {
        return new Promise((resolve, reject) => {
            if(! Prefixes.isValidPrefix(expected)) {
                reject(new NKeysError(NKeysErrorCode.InvalidPrefixByte));
                return;
            }
            Codec.decode(src)
                .then((buf: Buffer) => {
                    if (buf[0] != expected) {
                        reject(new NKeysError(NKeysErrorCode.InvalidPrefixByte));
                        return;
                    }
                    resolve(buf.slice(1))
                }).catch((err: Error) => {
                    reject(err);
                });
        });
    }


    static decodeSeed(src: string): Promise<SeedDecode> {
        return new Promise((resolve,reject) => {
            Codec.decode(src)
                .then((raw: Buffer) => {
                    if(raw.byteLength < 4) {
                        reject(new NKeysError(NKeysErrorCode.InvalidEncoding));
                        return;
                    }
                    let prefix = Codec.decodePrefix(raw);
                    if (prefix[0] != Prefix.Seed) {
                        reject(new NKeysError(NKeysErrorCode.InvalidSeed));
                        return;
                    }
                    if (!Prefixes.isValidPublicPrefix(prefix[1])) {
                        reject(new NKeysError(NKeysErrorCode.InvalidSeed));
                        return;
                    }
                    resolve({buf: raw.slice(2), prefix: prefix[1]})
                }).catch((err: Error) => {
                    reject(err);
                });
        });
    }

    static encodeSeed(role: Prefix, src: Buffer): Promise<string> {
        return new Promise((resolve,reject) => {
            if(! Buffer.isBuffer(src)) {
                reject(new NKeysError(NKeysErrorCode.SerializationError));
                return;
            }
            if(! Prefixes.isValidPublicPrefix(role)) {
                reject(new NKeysError(NKeysErrorCode.InvalidPrefixByte));
                return;
            }
            if(src.byteLength != ed25519.sign.secretKeyLength) {
                reject(new NKeysError(NKeysErrorCode.InvalidSeedLen));
                return;
            }
            // offsets for this token
            let payloadOffset = 2;
            let payloadLen = src.byteLength;
            let checkLen = 2;
            let cap = payloadOffset + payloadLen + checkLen;
            let checkOffset = payloadOffset + payloadLen;

            // make the prefixes human readable when encoded
            let prefix = Codec.encodePrefix(Prefix.Seed, role);

            let raw = new Buffer(cap);
            prefix.copy(raw,0,0);
            src.copy(raw, payloadOffset, 0);

            //calculate the checksum write it LE
            let checksum = crc16.checksum(raw.slice(0,checkOffset));
            raw.writeUInt16LE(checksum, checkOffset);

            // generate a string
            // generate a base32 string - remove the padding
            let str = b32enc(Codec.toArrayBuffer(raw), 'RFC3548');
            str = str.replace(/=+$/, '');
            resolve(str);
        });
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
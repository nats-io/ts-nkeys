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

import 'mocha';
import {expect} from 'chai';
import {Codec, SeedDecode} from '../src/codec';
import * as crypto from "crypto";
import {Prefix} from "../src/prefix";
import {NKeysError, NKeysErrorCode} from "../src/errors";

describe('Test Codec', () => {

    it('Should fail to encode non-Buffer', () => {
        //@ts-ignore
        return Codec.encode(Prefix.Private, 10)
            .catch((err: Error) => {
                expect(err).to.be.instanceof(Error);
                let e = err as NKeysError;
                expect(e.code).to.be.equal(NKeysErrorCode.SerializationError);
            });
    });

    it('Should fail to encode with invalid prefix', () => {
        let rand = crypto.randomBytes(32);
        return Codec.encode(13, rand)
            .catch((err: Error) => {
                expect(err).to.be.instanceof(Error);
                let e = err as NKeysError;
                expect(e.code).to.be.equal(NKeysErrorCode.InvalidPrefixByte);
            });
    });

    it('Should encode and decode', () => {
        let rand = crypto.randomBytes(32);
        return Codec.encode(Prefix.Private, rand)
            .then((str: string) => {
                expect(str).to.be.a('string');
                expect(str[0]).to.be.equal('P');
                return Codec.decode(str);
            })
            .then((buf: Buffer) => {
                expect(Buffer.isBuffer(buf)).to.be.true;
                expect(buf.byteLength).to.be.equal(rand.byteLength+1);
                expect(buf.readUInt8(0)).to.be.equal(Prefix.Private);
            });
    });

    it('Should fail to encode seeds that are not 64 bytes', () => {
        let rand = crypto.randomBytes(32);
        return Codec.encodeSeed(Prefix.Account, rand)
            .catch((err: Error) => {
                expect(err).to.be.instanceof(Error);
                let e = err as NKeysError;
                expect(e.code).to.be.equal(NKeysErrorCode.InvalidSeedLen);
            });
    });

    it('Should encode seed and decode account', () => {
        let rand = crypto.randomBytes(64);
        return Codec.encodeSeed(Prefix.Account, rand)
        .then((str: string) => {
            expect(str).to.be.a('string');
            expect(str[0]).to.be.equal('S');
            expect(str[1]).to.be.equal('A');
            return Codec.decodeExpectingPrefix(Prefix.Seed, str);
        })
        .then((buf: Buffer) => {
            expect(buf[0]).to.be.equal(Prefix.Account);
            expect(Buffer.isBuffer(buf)).to.be.true;
            expect(buf.slice(1)).to.be.eql(rand);
        })
    });

    it('Should encode and decode seed', () => {
        let rand = crypto.randomBytes(64);
        return Codec.encodeSeed(Prefix.Account, rand)
            .then((str: string) => {
                expect(str).to.be.a('string');
                expect(str[0]).to.be.equal('S');
                expect(str[1]).to.be.equal('A');
                return Codec.decodeSeed(str);
            })
            .then((seed: SeedDecode) => {
                expect(Buffer.isBuffer(seed.buf)).to.be.true;
                expect(seed.prefix).to.be.equal(Prefix.Account);
                expect(seed.buf).to.be.eql(rand);
            })
    });
});


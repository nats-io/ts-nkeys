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

import {Codec} from '../src/codec';
import * as crypto from "crypto";
import {NKeysErrorCode, Prefix} from "../src/nkeys";
import test from "ava";


test('Should fail to encode non-Buffer', (t) => {
    t.throws(() => {
        //@ts-ignore
        Codec.encode(Prefix.Private, 10);
    }, {code: NKeysErrorCode.SerializationError});
});

test('Should fail to encode with invalid prefix', (t) => {
    t.throws(() => {
        let rand = crypto.randomBytes(32);
        Codec.encode(13, rand);
    }, {code: NKeysErrorCode.InvalidPrefixByte});
});

test('Should encode and decode', (t) => {
    let rand = crypto.randomBytes(32);
    let enc = Codec.encode(Prefix.Private, rand);
    t.is(typeof enc, 'string');
    t.is(enc[0], 'P');

    let dec = Codec.decode(enc);
    t.true(Buffer.isBuffer(dec));
    t.is(dec[0], Prefix.Private);
    t.deepEqual(dec.slice(1), rand);
});

test('Should fail to encode seeds that are not 32 bytes', (t) => {
    t.throws(() => {
        let rand = crypto.randomBytes(64);
        Codec.encodeSeed(Prefix.Account, rand);
    }, {code: NKeysErrorCode.InvalidSeedLen});
});

test('Should encode seed and decode account', (t) => {
    let rand = crypto.randomBytes(32);
    let enc = Codec.encodeSeed(Prefix.Account, rand);
    t.is(typeof enc, 'string');
    t.is(enc[0], 'S');
    t.is(enc[1], 'A');

    let dec = Codec.decodeExpectingPrefix(Prefix.Seed, enc);
    t.true(Buffer.isBuffer(dec));
    t.is(dec[0], Prefix.Account);
    t.deepEqual(dec.slice(1), rand);
});

test('Should encode and decode seed', (t) => {
    let rand = crypto.randomBytes(32);
    let enc = Codec.encodeSeed(Prefix.Account, rand);
    t.is(typeof enc, 'string');
    t.is(enc[0], 'S');
    t.is(enc[1], 'A');

    let seed = Codec.decodeSeed(enc);
    t.true(Buffer.isBuffer(seed.buf));
    t.is(seed.prefix, Prefix.Account);
    t.deepEqual(seed.buf, rand);
});

test('should fail to decode non-base32', (t) => {
    t.throws(() => {
        Codec.decodeSeed("foo!");
    }, {code: NKeysErrorCode.InvalidEncoding});
});

test('should fail to short string', (t) => {
    t.throws(() => {
        Codec.decodeSeed("OK");
    }, {code: NKeysErrorCode.InvalidEncoding});
});

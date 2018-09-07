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
import b32enc = require('base32-encode');
import b32dec = require('base32-decode');
import {Prefix} from "../src/nkeys";
import * as util from "../src/util";
import test from "ava";


test('should encode seed', (t) => {
    let buf = Buffer.alloc(1);
    buf[0] = Prefix.Seed;

    let f = util.toArrayBuffer();
    let str = b32enc(f(buf), 'RFC3548');
    t.is(str[0],'S');

    let aout = b32dec(str, 'RFC3548');
    let bufout = Buffer.from(aout);
    t.deepEqual(bufout, buf);
});

test('should encode private', async(t) => {
    let buf = Buffer.alloc(1);
    buf[0] = Prefix.Private;

    let f = util.toArrayBuffer();
    let str = b32enc(f(buf), 'RFC3548');
    t.is(str[0],'P');

    let aout = b32dec(str, 'RFC3548');
    let bufout = Buffer.from(aout);
    t.deepEqual(bufout, buf);
});

test('should encode server', async (t) => {
    let buf = Buffer.alloc(1);
    buf[0] = Prefix.Server;

    let f = util.toArrayBuffer();
    let str = b32enc(f(buf), 'RFC3548');
    t.is(str[0],'N');

    let aout = b32dec(str, 'RFC3548');
    let bufout = Buffer.from(aout);
    t.deepEqual(bufout,buf);
});

test('should encode cluster', async(t) => {
    let buf = Buffer.alloc(1);
    buf[0] = Prefix.Cluster;

    let f = util.toArrayBuffer();
    let str = b32enc(f(buf), 'RFC3548');
    t.is(str[0],'C');

    let aout = b32dec(str, 'RFC3548');
    let bufout = Buffer.from(aout);
    t.deepEqual(bufout,buf);
});

test('should encode account', async(t) => {
    let buf = Buffer.alloc(1);
    buf[0] = Prefix.Account;

    let f = util.toArrayBuffer();
    let str = b32enc(f(buf), 'RFC3548');
    t.is(str[0], 'A');

    let aout = b32dec(str, 'RFC3548');
    let bufout = Buffer.from(aout);
    t.deepEqual(bufout,buf);
});

test('should encode user', async(t) => {
    let buf = Buffer.alloc(1);
    buf[0] = Prefix.User;

    let f = util.toArrayBuffer();
    let str = b32enc(f(buf), 'RFC3548');
    t.is(str[0],'U');

    let aout = b32dec(str, 'RFC3548');
    let bufout = Buffer.from(aout);
    t.deepEqual(bufout,buf);
});

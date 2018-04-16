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
import {expect} from 'chai'

import b32enc = require('base32-encode');
import b32dec = require('base32-decode');
import {Prefix} from "../src/nkeys";
import * as util from "../src/util";


describe('Should encode and decode prefixes', ()=> {
    it('should encode seed', () => {
        let buf = new Buffer(6);
        buf[0] = Prefix.Seed;

        let f = util.toArrayBuffer();
        let str = b32enc(f(buf), 'RFC3548');
        expect(str[0]).to.be.eql('S');

        let aout = b32dec(str, 'RFC3548');
        let bufout = Buffer.from(aout);
        expect(bufout).to.be.eql(buf);
    });

    it('should encode private', () => {
        let buf = new Buffer(6);
        buf[0] = Prefix.Private;

        let f = util.toArrayBuffer();
        let str = b32enc(f(buf), 'RFC3548');
        expect(str[0]).to.be.eql('P');

        let aout = b32dec(str, 'RFC3548');
        let bufout = Buffer.from(aout);
        expect(bufout).to.be.eql(buf);
    });

    it('should encode server', () => {
        let buf = new Buffer(6);
        buf[0] = Prefix.Server;

        let f = util.toArrayBuffer();
        let str = b32enc(f(buf), 'RFC3548');
        expect(str[0]).to.be.eql('N');

        let aout = b32dec(str, 'RFC3548');
        let bufout = Buffer.from(aout);
        expect(bufout).to.be.eql(buf);
    });

    it('should encode cluster', () => {
        let buf = new Buffer(6);
        buf[0] = Prefix.Cluster;

        let f = util.toArrayBuffer();
        let str = b32enc(f(buf), 'RFC3548');
        expect(str[0]).to.be.eql('C');

        let aout = b32dec(str, 'RFC3548');
        let bufout = Buffer.from(aout);
        expect(bufout).to.be.eql(buf);
    });

    it('should encode account', () => {
        let buf = new Buffer(6);
        buf[0] = Prefix.Account;

        let f = util.toArrayBuffer();
        let str = b32enc(f(buf), 'RFC3548');
        expect(str[0]).to.be.eql('A');

        let aout = b32dec(str, 'RFC3548');
        let bufout = Buffer.from(aout);
        expect(bufout).to.be.eql(buf);
    });

    it('should encode user', () => {
        let buf = new Buffer(6);
        buf[0] = Prefix.User;

        let f = util.toArrayBuffer();
        let str = b32enc(f(buf), 'RFC3548');
        expect(str[0]).to.be.eql('U');

        let aout = b32dec(str, 'RFC3548');
        let bufout = Buffer.from(aout);
        expect(bufout).to.be.eql(buf);
    });
});
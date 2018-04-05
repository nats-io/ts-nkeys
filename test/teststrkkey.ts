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

import {expect} from 'chai'
import 'mocha';
import crypto = require('crypto');
import {Prefix, Prefixes} from "../src/prefix";
import {TokenCodec} from "../src/strkey";


describe('Codec', ()=> {
    it('should encode', () => {
        let buf = crypto.randomBytes(32);
        let v = TokenCodec.encode(Prefix.User, buf);
        expect(v).to.be.a('string');
        expect(v).not.to.be.empty;
    });

    it('should fail to encode non buffer',() => {
        let buf = 22<<3;
        // @ts-ignore - this is actually an error for ts, but not in javascript.
        let v = TokenCodec.encode(Prefix.User, buf);
        expect(v).to.be.an('error');
    });


    it('should decode', () => {
        let buf = crypto.randomBytes(32);
        let v = TokenCodec.encode(Prefix.User, buf) as string;
        expect(v).to.be.a('string');

        let decoded = TokenCodec.decode(v) as Buffer;
        expect(buf).to.be.instanceof(Buffer);

        // the first byte is the prefix
        let prefix = Prefixes.parsePrefix(decoded.readUInt8(0));
        expect(prefix).to.equal(Prefix.User);
        let payload = decoded.slice(1);
        expect(buf).to.be.eql(payload);
    });
});




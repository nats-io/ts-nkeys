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
import { crc16 } from '../src/crc16';


describe('CRC16', ()=> {
    it('should return [0xC8, 0xB2] given [0x41, 0x4C, 0x42, 0x45, 0x52, 0x54, 0x4F]', () => {
        const buf = new Uint8Array([0x41, 0x4C, 0x42, 0x45, 0x52, 0x54, 0x4F]);
        const crc = crc16.checksum(Buffer.from(buf));
        expect(crc).to.eql(51378);
    });

    it('should validate [0xC8, 0xB2] given [0x41, 0x4C, 0x42, 0x45, 0x52, 0x54, 0x4F]', () => {
        const buf = new Uint8Array([0x41, 0x4C, 0x42, 0x45, 0x52, 0x54, 0x4F]);
        const ok = crc16.validate(Buffer.from(buf), 51378);
        expect(ok).to.be.true;

    });

    it('should reject [0xCA, 0xB2] given [0x41, 0x4C, 0x42, 0x45, 0x52, 0x54, 0x4F]', () => {
        const buf = new Uint8Array([0x41, 0x4C, 0x42, 0x45, 0x52, 0x54, 0x4F]);
        const ok = crc16.validate(Buffer.from(buf), 12345);
        expect(ok).to.be.false;
    });
});
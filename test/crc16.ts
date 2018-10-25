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

import { crc16 } from '../src/crc16';
import test, {ExecutionContext} from "ava";

test('should return [0xC8, 0xB2] given [0x41, 0x4C, 0x42, 0x45, 0x52, 0x54, 0x4F]', (t) => {
    const buf = new Uint8Array([0x41, 0x4C, 0x42, 0x45, 0x52, 0x54, 0x4F]);
    const crc = crc16.checksum(Buffer.from(buf.buffer));
    t.is(crc,51378);
});

test('should validate [0xC8, 0xB2] given [0x41, 0x4C, 0x42, 0x45, 0x52, 0x54, 0x4F]', (t) => {
    const buf = new Uint8Array([0x41, 0x4C, 0x42, 0x45, 0x52, 0x54, 0x4F]);
    const ok = crc16.validate(Buffer.from(buf.buffer), 51378);
    t.true(ok);

});

test('should reject [0xCA, 0xB2] given [0x41, 0x4C, 0x42, 0x45, 0x52, 0x54, 0x4F]', (t) => {
    const buf = new Uint8Array([0x41, 0x4C, 0x42, 0x45, 0x52, 0x54, 0x4F]);
    const ok = crc16.validate(Buffer.from(buf.buffer), 12345);
    t.false(ok);
});


function crc16Macro(t: ExecutionContext , input: Buffer, eck: number, validates: boolean) {
    let ck = crc16.checksum(input);
    t.is(ck, eck, "checksums");
    t.is(crc16.validate(input, eck), validates);
}

test('empty string', crc16Macro, Buffer.from(""), 0, true);
test('abc', crc16Macro, Buffer.from("abc"), 0x9DD6, true);
test('ABC', crc16Macro, Buffer.from("ABC"), 0x3994, true);
test('this is a string', crc16Macro, Buffer.from("This is a string"), 0x21E3, true);
test('123456789', crc16Macro, Buffer.from("123456789"), 0x31C3, true);
test('0x7F', crc16Macro, Buffer.from([0x7F]), 0x8F78, true);
test('0x80', crc16Macro, Buffer.from([0x80]), 0x9188, true);
test('0xFF', crc16Macro, Buffer.from([0xFF]), 0x1EF0, true);
test('0x0,0x1,0x7D,0x7E, 0x7F, 0x80, 0xFE, 0xFF', crc16Macro, Buffer.from([0x0,0x1,0x7D,0x7E, 0x7F, 0x80, 0xFE, 0xFF]), 0xE26F, true);
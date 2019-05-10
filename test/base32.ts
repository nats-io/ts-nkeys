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

import test, {ExecutionContext} from "ava";
import {base32} from "../src/base32";


function base32Macro(t: ExecutionContext , input: Buffer|string, expected: string) {
    t.plan(2);

    //@ts-ignore
    let enc = base32.encode(Buffer.from(input));
    t.deepEqual(enc, Buffer.from(expected));

    let dec = base32.decode(Buffer.from(expected));
    //@ts-ignore
    t.deepEqual(dec, Buffer.from(input))
}

// Tests copied from go library
// https://tools.ietf.org/html/rfc4648 and wikipedia ported
test('empty string', base32Macro, "", "");
test('f', base32Macro, Buffer.from("f"), "MY");
test('fo', base32Macro, Buffer.from("fo"), "MZXQ");
test('foo', base32Macro, Buffer.from("foo"), "MZXW6");
test('foob', base32Macro, Buffer.from("foob"), "MZXW6YQ");
test('fooba', base32Macro, Buffer.from("fooba"), "MZXW6YTB");
test('foobar', base32Macro, Buffer.from("foobar"), "MZXW6YTBOI");
test('sure.', base32Macro, Buffer.from("sure."), "ON2XEZJO");
test('sure', base32Macro, Buffer.from("sure"), "ON2XEZI");
test('sur', base32Macro, Buffer.from("sur"), "ON2XE");
test('su', base32Macro, Buffer.from("su"), "ON2Q");
test('leasure.', base32Macro, Buffer.from("leasure."), "NRSWC43VOJSS4");
test('easure.', base32Macro, Buffer.from("easure."), "MVQXG5LSMUXA");
test('asure.', base32Macro, Buffer.from("asure."), "MFZXK4TFFY");

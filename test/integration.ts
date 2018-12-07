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

import test from "ava";
import {fromPublic, fromSeed, Prefix} from "../src/nkeys";
import {Codec} from '../src/codec';


// this was generated using nkey api in go
let data = {
    "seed": "SAAK7IAXLQQ2A65HJCMUBR6IG6GP3AOXQGEPCNQIIAG7ZZ7XCEFIROMY6U",
    "public_key": "ACLG5IASA6EMBRAUOXXWX44GNBZPDJO3A3RYDT7FDYYEPBJIBRGP6WHZ",
    "nonce": "2w2TrJVMAqwqZbg0nXovhQ==",
    "sig": "F64qNsH2n_XllIX7qYa1YqTTH_K61tPHlvvsN_lhlo-tCpTaKfp0_yWnw5IsQeaiSqwN2rUs20Rk1VV9vtiBBw=="
};

test('verify', (t) => {
    t.plan(2);
    let pk = fromPublic(Buffer.from(data.public_key));
    let ok = pk.verify(Buffer.from(data.nonce), Buffer.from(data.sig, 'base64'));
    t.true(ok);

    let seed = fromSeed(Buffer.from(data.seed));
    ok = seed.verify(Buffer.from(data.nonce), Buffer.from(data.sig, 'base64'));
    t.true(ok);
});



test('encoded seed returns stable values albertor', (t) => {
    let data = {
            "seed": "SUAGC3DCMVZHI33SMFWGEZLSORXXEYLMMJSXE5DPOJQWYYTFOJ2G64VAPY",
            "public_key": "UAHJLSMYZDJCBHQ2SARL37IEALR3TI7VVPZ2MJ7F4SZKNOG7HJJIYW5T",
            "private_key": "PBQWYYTFOJ2G64TBNRRGK4TUN5ZGC3DCMVZHI33SMFWGEZLSORXXEDUVZGMMRURATYNJAIV57UCAFY5ZUP22X45GE7S6JMVGXDPTUUUMRKXA",
            "nonce": "",
            "sig": ""
        };

    let v = Codec.encodeSeed(Prefix.User, Buffer.from("albertoralbertoralbertoralbertor"));
    t.is(v.toString('ascii'), data.seed);

    var kp = fromSeed(v)
    t.is(kp.getSeed().toString('ascii'), data.seed, "seed");
    t.is(kp.getPublicKey().toString('ascii'), data.public_key, "public key");
    t.is(kp.getPrivateKey().toString('ascii'), data.private_key, "private key");
});

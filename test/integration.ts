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
import {fromPublic, fromSeed} from "../src/nkeys";

// this was generated using nkey api in go
let data = {
    "seed": "SAADQYV2GFYCKXPG5IG6BOPAIKQPFCQAIK3IIIIIQPXKIQUQTKJAFDPJH5E6MKWIT2QSCSC77YMJQP55BKKFKUC3YVWCTZQPIA2JEF2RJOBT4",
    "public_key": "ADUT6SPGFLEJ5IJBJBP74GEYH66QVFCVKBN4K3BJ4YHUANESC5IUXPO7",
    "nonce": "yaefGpCIUh-G35PertpItw==",
    "sig": "n91875Rvbj7MOqo14a5JWBvJ7t5gjsoJmZayLZdX6KfOb-oLlgH2m1C43GpxmoYucgIRsWzMrDGX3wyPgWh8Cw=="
};

test('verify', async (t) => {
    t.plan(2);
    let pk = await fromPublic(data.public_key);
    let ok = await pk.verify(Buffer.from(data.nonce), Buffer.from(data.sig, 'base64'));
    t.true(ok);

    let seed = await fromSeed(data.seed);
    ok = await seed.verify(Buffer.from(data.nonce), Buffer.from(data.sig, 'base64'));
    t.true(ok);
});

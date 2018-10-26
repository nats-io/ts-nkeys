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

import * as ed25519 from "tweetnacl";
import {Codec} from "./codec";
import {KeyPair, Prefix} from "./nkeys";

export class KP implements KeyPair {
    seed: string;
    constructor(seed: string) {
        this.seed = seed;
    }

    getRawSeed(): Buffer {
        let sd = Codec.decodeSeed(this.seed);
        return sd.buf
    }

    getSeed(): string {
        return this.seed;
    }

    getPublicKey(): string {
        let sd = Codec.decodeSeed(this.seed);
        let kp = ed25519.sign.keyPair.fromSeed(this.getRawSeed());
        return Codec.encode(sd.prefix, Buffer.from(kp.publicKey))
    };

    getPrivateKey(): string {
        let kp = ed25519.sign.keyPair.fromSeed(this.getRawSeed());
        return Codec.encode(Prefix.Private, Buffer.from(kp.secretKey))
    }

    sign(input: Buffer): Buffer {
        let kp = ed25519.sign.keyPair.fromSeed(this.getRawSeed());
        let a = ed25519.sign.detached(input, kp.secretKey);
        return Buffer.from(a.buffer);
    }

    verify(input: Buffer, sig: Buffer): boolean {
        let kp = ed25519.sign.keyPair.fromSeed(this.getRawSeed());
        return ed25519.sign.detached.verify(input, sig, kp.publicKey);
    }
}
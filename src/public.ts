/*
 * Copyright 2018-2020 The NATS Authors
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

import ed25519 = require('tweetnacl');
import {Codec} from "./codec";
import {KeyPair, NKeysError, NKeysErrorCode} from "./nkeys";

/**
 * KeyPair capable of verifying only
 */
export class PublicKey implements KeyPair {
    publicKey: Buffer;

    constructor(publicKey: Buffer) {
        this.publicKey = publicKey;
    }

    getPublicKey(): Buffer {
        return this.publicKey;
    }

    getPrivateKey(): Buffer {
        throw new NKeysError(NKeysErrorCode.PublicKeyOnly);
    }

    getSeed(): Buffer {
        throw new NKeysError(NKeysErrorCode.PublicKeyOnly);
    }

    sign(_: Buffer): Buffer {
        throw new NKeysError(NKeysErrorCode.CannotSign);
    }

    verify(input: Buffer, sig: Buffer): boolean {
        let buf = Codec._decode(this.publicKey);
        return ed25519.sign.detached.verify(input, sig, buf.slice(1));
    }
}
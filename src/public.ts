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

import {KeyPair} from "./keypair";
import {NKeysError, NKeysErrorCode} from "./errors";
import {TokenCodec} from "./strkey";
import ed25519 = require('tweetnacl')

/**
 * KeyPair capable of verifying only
 */
export class PublicKey implements KeyPair {
    publicKey: string;

    constructor(publicKey: string) {
        this.publicKey = publicKey;
    }

    getPublicKey(): string | Error {
        return this.publicKey;
    }

    getPrivateKey(): string | Error {
        return new NKeysError(NKeysErrorCode.PublicKeyOnly);
    }

    getSeed(): string | Error {
        return new NKeysError(NKeysErrorCode.PublicKeyOnly);
    }

    sign(input: Buffer): Buffer | Error {
        return new NKeysError(NKeysErrorCode.CannotSign);
    }

    verify(input: Buffer, sig: Buffer): boolean {
        let raw = TokenCodec.decode(this.publicKey);
        if(raw instanceof Error) {
            return false;
        }
        return ed25519.sign.detached.verify(input, sig, raw.slice(1))
    }
}
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

import ed25519 = require('tweetnacl')
import {Codec} from "./codec";
import {KeyPair, NKeysError, NKeysErrorCode} from "./nkeys";

/**
 * KeyPair capable of verifying only
 */
export class PublicKey implements KeyPair {
    publicKey: string;

    constructor(publicKey: string) {
        this.publicKey = publicKey;
    }

    getPublicKey(): Promise<string> {
        return new Promise((resolve, reject) => {
            resolve(this.publicKey);
        });
    }

    getPrivateKey(): Promise<string> {
        return new Promise((resolve,reject) => {
            reject(new NKeysError(NKeysErrorCode.PublicKeyOnly));
            return;
        });
    }

    getSeed(): Promise<string> {
        return new Promise((resolve,reject) => {
            reject(new NKeysError(NKeysErrorCode.PublicKeyOnly));
            return;
        });
    }

    sign(input: Buffer): Promise<Buffer> {
        return new Promise((resolve, reject) => {
            reject(new NKeysError(NKeysErrorCode.CannotSign));
            return;
        });
    }

    verify(input: Buffer, sig: Buffer): Promise<boolean> {
        return new Promise((resolve, reject) => {
            Codec.decode(this.publicKey)
                .then((buf: Buffer) => {
                   resolve(ed25519.sign.detached.verify(input, sig, buf.slice(1)));
                });
        });
    }
}
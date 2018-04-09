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

import {SignKeyPair} from "tweetnacl";
import {KeyPair} from "./keypair";
import {Prefix} from "./prefix";
import {Codec, SeedDecode} from "./codec";
import * as ed25519 from "tweetnacl";

export class KP implements KeyPair {
    seed: string;
    constructor(seed: string) {
        this.seed = seed;
    }

    getRawSeed(): Promise<Buffer> {
        return new Promise((resolve, reject) => {
        Codec.decodeSeed(this.seed)
            .then((ds: SeedDecode) => {
                resolve(ds.buf);
            })
            .catch((err: Error) => {
                reject(err);
            });
        });
    }

    getKeys(): Promise<SignKeyPair> {
        return new Promise((resolve, reject) => {
            this.getRawSeed()
                .then((raw: Buffer) => {
                    let skp = ed25519.sign.keyPair.fromSecretKey(raw);
                    resolve(skp);
                })
                .catch((err: Error) => {
                    reject(err);
                });
        })
    }

    getSeed(): Promise<string> {
        return new Promise((resolve, reject) => {
            resolve(this.seed);
        });
    }

    getPublicKey(): Promise<string> {
        return new Promise((resolve, reject) => {
            Codec.decodeSeed(this.seed)
                .then((ds: SeedDecode) => {
                    let pub = ed25519.sign.keyPair.fromSecretKey(ds.buf);
                    Codec.encode(ds.prefix, Buffer.from(pub.publicKey.buffer))
                        .then((pk: string) => {
                            resolve(pk);
                        });
                })
                .catch((err: Error) => {
                    reject(err);
                });
        });
    }

    getPrivateKey(): Promise<string> {
        return new Promise((resolve, reject) => {
            this.getKeys()
                .then((kp: SignKeyPair) => {
                    Codec.encode(Prefix.Private, Buffer.from(kp.secretKey.buffer))
                        .then((pk: string) => {
                           resolve(pk);
                        });
                })
                .catch((err: Error) => {
                    reject(err);
                });
        });
    }


    sign(input: Buffer): Promise<Buffer> {
        return new Promise((resolve, reject) => {
            this.getKeys()
                .then((kp: SignKeyPair) => {
                    let a = ed25519.sign.detached(input, kp.secretKey);
                    resolve(Buffer.from(a.buffer));
                }).catch((err: Error) => {
                    reject(err);
                });
        });
    }

    verify(input: Buffer, sig: Buffer): Promise<boolean> {
        return new Promise((resolve, reject) => {
            this.getKeys()
                .then((sk: SignKeyPair) => {
                    let ok = ed25519.sign.detached.verify(input, sig, sk.publicKey);
                    resolve(ok);
                }).catch((err: Error) => {
                    reject(err);
                });
        });
    }
}
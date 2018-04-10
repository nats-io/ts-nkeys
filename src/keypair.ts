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


import {KP} from "./kp";
import {PublicKey} from "./public";
import {NKeysError, NKeysErrorCode} from "./errors";
import {Codec, SeedDecode} from "./codec";
import {Prefix} from "./prefix";
import {Prefixes} from "./prefix";
import ed25519 = require('tweetnacl');

export const VERSION = "0.0.1";

export function createPair(prefix: Prefix, seed?: Buffer): Promise<KeyPair> {
    return new Promise((resolve, reject) => {
        if (!seed) {
            seed = Buffer.from(ed25519.randomBytes(32).buffer);
        }
        if (!Buffer.isBuffer(seed)) {
            reject(new NKeysError(NKeysErrorCode.InvalidPublicKey));
            return;
        }

        let kp = ed25519.sign.keyPair.fromSeed(seed);
        Codec.encodeSeed(prefix, Buffer.from(kp.secretKey.buffer))
            .then((str: string) => {
                resolve(new KP(str));
            }).catch((err: Error) => {
                reject(err);
                return;
            });
    })
}

export function createAccount(src?: Buffer): Promise<KeyPair> {
    return createPair(Prefix.Account, src);
}

export function createUser(src?: Buffer): Promise<KeyPair> {
    return createPair(Prefix.User, src);
}

export function createCluster(src?: Buffer): Promise<KeyPair> {
    return createPair(Prefix.Cluster, src);
}

export function createServer(src?: Buffer): Promise<KeyPair> {
    return createPair(Prefix.Server, src);
}

export function fromPublic(src: string): Promise<KeyPair> {
    return new Promise((resolve, reject) => {
        Codec.decode(src)
            .then((raw: Buffer) => {
                let prefix = Prefixes.parsePrefix(raw.readUInt8(0))
                if (Prefixes.isValidPublicPrefix(prefix)) {
                    resolve(new PublicKey(src));
                }
                reject(new NKeysError(NKeysErrorCode.InvalidPublicKey));
                return;
            })
            .catch((err: Error) => {
                reject(err);
            });
    });
}

export function fromSeed(src: string): Promise<KeyPair> {
    return new Promise((resolve, reject) => {
        Codec.decodeSeed(src)
            .then((sd: SeedDecode) => {
                resolve(new KP(src))
            }).catch((err: Error) => {
                reject(err);
            });
    });
}



export interface KeyPair {
    /**
     * Returns the public key associated with the KeyPair
     * @returns {Promise<string>}
     */
    getPublicKey(): Promise<string>;

    /**
     * Returns the private key associated with the KeyPair
     * @returns {Promise<string>}
     */
    getPrivateKey(): Promise<string>;

    /**
     * Returns the PrivateKey's seed.
     * @returns {Promise<string>}
     */
    getSeed() : Promise<string>;

    /**
     * Returns the digital signature of signing the input with the
     * the KeyPair's private key.
     * @param {Buffer} input
     * @returns {Promise<Buffer>}
     */
    sign(input: Buffer): Promise<Buffer>;

    /**
     * Returns true if the signature can be verified with the KeyPair
     * @param {Buffer} input
     * @param {Buffer} sig
     * @returns {Promise<boolean>}
     */
    verify(input: Buffer, sig: Buffer) : Promise<boolean>;
}


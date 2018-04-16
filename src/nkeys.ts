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
import {KP} from "./kp";
import {PublicKey} from "./public";
import {Codec, SeedDecode} from "./codec";

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
                let prefix = Prefixes.parsePrefix(raw.readUInt8(0));
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
            .then((_: SeedDecode) => {
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

export enum Prefix {
    //Seed is the version byte used for encoded NATS Seeds
    Seed = 18 << 3, // Base32-encodes to 'S...'

    //PrefixBytePrivate is the version byte used for encoded NATS Private keys
    Private = 15 << 3, // Base32-encodes to 'P...'

    //PrefixByteServer is the version byte used for encoded NATS Servers
    Server = 13 << 3, // Base32-encodes to 'N...'

    //PrefixByteCluster is the version byte used for encoded NATS Clusters
    Cluster = 2 << 3, // Base32-encodes to 'C...'

    //PrefixByteAccount is the version byte used for encoded NATS Accounts
    Account = 0, // Base32-encodes to 'A...'

    //PrefixByteUser is the version byte used for encoded NATS Users
    User = 20 << 3, // Base32-encodes to 'U...'
}

/**
 * Internal utility for testing prefixes
 */
export class Prefixes {
    static isValidPublicPrefix(prefix: Prefix): boolean {
        return prefix == Prefix.Server
            || prefix == Prefix.Cluster
            || prefix == Prefix.Account
            || prefix == Prefix.User;
    }

    static startsWithValidPrefix(s: string) {
        let c = s[0];
        return c == 'S' || c == 'P' || c == 'N' || c == 'C' || c == 'A' || c == 'U';
    }

    static isValidPrefix(prefix: Prefix) : boolean {
        let v = this.parsePrefix(prefix);
        return v != -1;
    }

    static parsePrefix(v: number) : Prefix {
        switch (v) {
            case Prefix.Seed:
                return Prefix.Seed;
            case Prefix.Private:
                return Prefix.Private;
            case Prefix.Server:
                return Prefix.Server;
            case Prefix.Cluster:
                return Prefix.Cluster;
            case Prefix.Account:
                return Prefix.Account;
            case Prefix.User:
                return Prefix.User;
            default:
                return -1;
        }
    }
}

export enum NKeysErrorCode {
    InvalidPrefixByte = "nkeys: invalid prefix byte",
    InvalidKey        = "nkeys: invalid key",
    InvalidPublicKey  = "nkeys: invalid public key",
    InvalidSeedLen    = "nkeys: invalid seed length",
    InvalidSeed       = "nkeys: invalid seed",
    InvalidEncoding   = "nkeys: invalid encoded key",
    InvalidSignature  = "nkeys: signature verification failed",
    CannotSign        = "nkeys: can not sign, no private key available",
    PublicKeyOnly     = "nkeys: no seed or private key available",
    InvalidChecksum   = "nkeys: invalid checksum",
    SerializationError   = "nkeys: serialization error"
}

export class NKeysError extends Error {
    name: string;
    code: string;
    chainedError?: Error;

    /**
     * @param {NKeysErrorCode} code
     * @param {Error} [chainedError]
     * @constructor
     *
     * @api private
     */
    constructor(code: NKeysErrorCode, chainedError?: Error) {
        super(code);
        Error.captureStackTrace(this, this.constructor);
        this.name = "NKeysError";
        this.code = code;
        this.chainedError = chainedError;
    }
}
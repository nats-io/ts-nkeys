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
import {Codec} from "./codec";

export const VERSION = "1.0.14";

export function createPair(prefix: Prefix): KeyPair {
    let rawSeed = ed25519.randomBytes(32).buffer;
    let str = Codec.encodeSeed(prefix, Buffer.from(rawSeed));
    return new KP(str);
}

export function createAccount(): KeyPair {
    return createPair(Prefix.Account);
}

export function createUser(): KeyPair {
    return createPair(Prefix.User);
}

export function createOperator(): KeyPair {
    return createPair(Prefix.Operator);
}

export function createCluster(): KeyPair {
    return createPair(Prefix.Cluster);
}

export function createServer(): KeyPair {
    return createPair(Prefix.Server);
}

export function fromPublic(src: Buffer): KeyPair {
    let raw = Codec._decode(src);
    let prefix = Prefixes.parsePrefix(raw.readUInt8(0));
    if (Prefixes.isValidPublicPrefix(prefix)) {
        return new PublicKey(src);
    }
    throw new NKeysError(NKeysErrorCode.InvalidPublicKey);
}

export function fromSeed(src: Buffer): KeyPair {
    Codec.decodeSeed(src);
    // if we are here it decoded
    return new KP(src);
}



export interface KeyPair {
    /**
     * Returns the public key associated with the KeyPair
     * @returns {Promise<string>}
     * @throws NKeysError
     */
    getPublicKey(): Buffer;

    /**
     * Returns the private key associated with the KeyPair
     * @returns Buffer
     * @throws NKeysError
     */
    getPrivateKey(): Buffer;

    /**
     * Returns the PrivateKey's seed.
     * @returns Buffer
     * @throws NKeysError
     */
    getSeed() : Buffer;

    /**
     * Returns the digital signature of signing the input with the
     * the KeyPair's private key.
     * @param {Buffer} input
     * @returns Buffer
     * @throws NKeysError
     */
    sign(input: Buffer): Buffer;

    /**
     * Returns true if the signature can be verified with the KeyPair
     * @param {Buffer} input
     * @param {Buffer} sig
     * @returns {boolean}
     * @throws NKeysError
     */
    verify(input: Buffer, sig: Buffer) : boolean;
}

export enum Prefix {
    //Seed is the version byte used for encoded NATS Seeds
    Seed = 18 << 3, // Base32-encodes to 'S...'

    //PrefixBytePrivate is the version byte used for encoded NATS Private keys
    Private = 15 << 3, // Base32-encodes to 'P...'

    //PrefixByteOperator is the version byte used for encoded NATS Operators
    Operator = 14 << 3, // Base32-encodes to 'O...'

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
            || prefix == Prefix.Operator
            || prefix == Prefix.Cluster
            || prefix == Prefix.Account
            || prefix == Prefix.User;
    }

    static startsWithValidPrefix(s: string) {
        let c = s[0];
        return c == 'S' || c == 'P' || c == 'O' || c == 'N' || c == 'C' || c == 'A' || c == 'U';
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
            case Prefix.Operator:
                return Prefix.Operator;
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
    SerializationError   = "nkeys: serialization error",
    ApiError          = "nkeys: api error"
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

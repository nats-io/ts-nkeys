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

import {Prefix} from "./prefix";
import ed25519 = require('tweetnacl')
import {TokenCodec, Token} from "./strkey";
import {NKeysError, NKeysErrorCode} from "./errors";
import {PublicKey} from "./public";
import {SignKeyPair} from "tweetnacl";

export interface KeyPair {
    /**
     * Returns the public key associated with the KeyPair
     * @returns {string | Error}
     */
    getPublicKey(): string | Error;

    /**
     * Returns the private key associated with the KeyPair
     * @returns {string | Error}
     */
    getPrivateKey(): string | Error;

    /**
     * Returns the PrivateKey's seed.
     * @returns {string | Error}
     */
    getSeed() : string | Error;

    /**
     * Returns the digital signature of signing the input with the
     * the KeyPair's private key.
     * @param {Buffer} input
     * @returns {Buffer | Error}
     */
    sign(input: Buffer): Buffer | Error;

    /**
     * Returns true if the signature can be verified with the KeyPair
     * @param {Buffer} input
     * @param {Buffer} sig
     * @returns {boolean}
     */
    verify(input: Buffer, sig: Buffer) : boolean;
}


export class KP implements KeyPair {
    seed: string;

    constructor(seed: string) {
        this.seed = seed;
    }

    getRawSeed() : Buffer | Error {
        let t = Token.decode(this.seed, true);
        return t.getKey();
    }

    getKeys(): SignKeyPair | Error {
        let raw = this.getRawSeed();
        if(raw instanceof Error) {
            return raw;
        }
        return ed25519.sign.keyPair.fromSecretKey(raw.slice(1));
    }

    getPrivateKey(): string | Error {
        let skp = this.getKeys();
        if(skp instanceof Error) {
            return skp;
        }
        return TokenCodec.encode(Prefix.Private, Buffer.from(skp.secretKey));
    }

    getPublicKey(): string | Error {
        let t = Token.decode(this.seed, true);
        let raw = t.getKey().slice(1);
        let kp = ed25519.sign.keyPair.fromSecretKey(raw);
        return TokenCodec.encode(t.getPublic(), Buffer.from(kp.publicKey));
    }

    getSeed(): string | Error {
        return this.seed;
    }

    sign(input: Buffer): Buffer | Error {
        let skp = this.getKeys();
        if(skp instanceof Error) {
            return skp;
        }
        return Buffer.from(ed25519.sign.detached(input, skp.secretKey));
    }

    verify(input: Buffer, sig: Buffer): boolean {
        let skp = this.getKeys();
        if (skp instanceof Error) {
            return false;
        }
        return ed25519.sign.detached.verify(input, sig, skp.publicKey);
    }

    private static createPair(prefix: Prefix, seed?: Buffer) : KeyPair | Error {
        if(!seed) {
            seed = Buffer.from(ed25519.randomBytes(32).buffer);
        }
        if(!Buffer.isBuffer(seed)){
            return new NKeysError(NKeysErrorCode.InvalidPublicKey);
        }

        let kp = ed25519.sign.keyPair.fromSeed(seed);
        let es = TokenCodec.encodeSeed(prefix, Buffer.from(kp.secretKey));
        if(es instanceof Error) {
            return es;
        }
        return new KP(es);
    }

    static createAccount(src?: Buffer) : KeyPair | Error {
        return KP.createPair(Prefix.Account, src);
    }

    static createUser(src?: Buffer) : KeyPair | Error {
        return KP.createPair(Prefix.User, src);
    }

    static createCluster(src?: Buffer) : KeyPair | Error {
        return KP.createPair(Prefix.Cluster, src);
    }

    static createServer(src?: Buffer) : KeyPair | Error {
        return KP.createPair(Prefix.Server, src);
    }

    static fromPublic(src: string) : KeyPair | Error {
        let t = Token.decode(src, false);
        if(!t.hasPublicPrefix()) {
            return new NKeysError(NKeysErrorCode.InvalidPublicKey)
        }
        return new PublicKey(src);
    }

    static fromSeed(src: string) : KeyPair | Error {
        let t = Token.decode(src, true);
        if(t instanceof Error) {
            return t;
        }
        return new KP(src);
    }
}


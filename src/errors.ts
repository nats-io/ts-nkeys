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
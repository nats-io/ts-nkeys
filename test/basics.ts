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

import 'mocha';
import {expect} from 'chai'

import ed25519 = require('tweetnacl');
import * as nkeys from "../src/keypair";
import {fromPublic} from "../src/keypair";
import {NKeysError, NKeysErrorCode} from "../src/errors";


describe('Test KeyPair', ()=> {
    it('Test Account', () => {
        let account: nkeys.KeyPair;
        let data = Buffer.from("HelloWorld");

        return nkeys.createAccount()
            .then((acc: nkeys.KeyPair) => {
                expect(acc).not.to.be.null;
                account = acc;
                return Promise.all([
                    account.getSeed(),
                    account.getPublicKey(),
                    account.getPrivateKey()
                ]);
            }).then((a: string[]) => {
                let seed = a[0];
                expect(seed).to.be.a('string');
                expect(seed[0]).to.be.equal('S');
                expect(seed[1]).to.be.equal('A');

                let publicKey = a[1];
                expect(publicKey).to.be.a('string');
                expect(publicKey[0]).to.be.equal('A');

                let privateKey = a[2];
                expect(privateKey).to.be.a('string');
                expect(privateKey[0]).to.be.equal('P');

                return account.sign(data);
            }).then((sig: Buffer) => {
                expect(sig).length(ed25519.sign.signatureLength);
                return account.verify(data, sig)
            }).then((ok: boolean) => {
                expect(ok).to.be.true;
            });
    });

    it('Test User', () => {
        return nkeys.createUser()
            .then((u: nkeys.KeyPair) => {
                return u.getPublicKey();
            }).then((pub: string) => {
                expect(pub).to.be.a('string');
                expect(pub[0]).to.be.equal('U');
            });
    });

    it('Test Cluster', () => {
        return nkeys.createCluster()
            .then((c: nkeys.KeyPair) => {
                return c.getPublicKey();
            }).then((pub: string) => {
                expect(pub).to.be.a('string');
                expect(pub[0]).to.be.equal('C');
            });
    });

    it('Test Server', () => {
        return nkeys.createServer()
            .then((s: nkeys.KeyPair) => {
                return s.getPublicKey();
            }).then((pub: string) => {
                expect(pub).to.be.a('string');
                expect(pub[0]).to.be.equal('N');
            });
    });

    it('Test From Public', () => {
        let user: nkeys.KeyPair;
        let pubUser1: nkeys.KeyPair;
        let pubUser2: nkeys.KeyPair;
        let pubKey: string;
        let data = Buffer.from("HelloWorld");

        return nkeys.createUser()
            .then((u: nkeys.KeyPair) => {
                user = u;
                return user.getPublicKey();
            }).then((pk: string) => {
                pubKey = pk;
                return Promise.all([
                    fromPublic(pubKey),
                    fromPublic(pubKey)]);
            }).then((kp: nkeys.KeyPair[]) => {
                pubUser1 = kp[0];
                pubUser2 = kp[1];
                return Promise.all([
                    pubUser1.getPublicKey(),
                    pubUser2.getPublicKey()
                ]);
            }).then((keys: string[]) => {
                expect(keys[0]).to.equal(keys[1]);
                return pubUser1.getPrivateKey()
            }).catch((error: Error) => {
                expect(error).to.be.instanceof(Error);
                let nerr : NKeysError = error as NKeysError;
                expect(nerr.code).to.be.equal(NKeysErrorCode.PublicKeyOnly);
                return pubUser1.getSeed()
            }).catch((error: Error) => {
                expect(error).to.be.instanceof(Error);
                let nerr : NKeysError = error as NKeysError;
                expect(nerr.code).to.be.equal(NKeysErrorCode.PublicKeyOnly);
                return pubUser1.sign(data);
            }).catch((error: Error) => {
                expect(error).to.be.instanceof(Error);
                let nerr : NKeysError = error as NKeysError;
                expect(nerr.code).to.be.equal(NKeysErrorCode.CannotSign);

                return user.sign(data);
            }).then((signature: any) => {
                return Promise.all([
                    user.verify(data, signature),
                    pubUser1.verify(data, signature),
                    pubUser2.verify(data, signature)
                ])
            }).then((verifications: boolean[]) => {
                expect(verifications[0]).to.be.true;
                expect(verifications[1]).to.be.true;
                expect(verifications[2]).to.be.true;
            })

    });
});
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
import * as assert from "assert";
import {KP} from "../src/kp";
import {SignKeyPair} from "tweetnacl";
import {Codec, SeedDecode} from "../src/codec";
import {
    createAccount,
    createCluster,
    createPair,
    createServer,
    createUser,
    fromPublic,
    fromSeed,
    KeyPair,
    NKeysError,
    NKeysErrorCode,
    Prefix
} from "../src/nkeys";




describe('Test KeyPair', ()=> {
    it('Test Account', () => {
        let account: KeyPair;
        let data = Buffer.from("HelloWorld");

        return createAccount()
            .then((acc: KeyPair) => {
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
        return createUser()
            .then((u: KeyPair) => {
                return u.getPublicKey();
            }).then((pub: string) => {
                expect(pub).to.be.a('string');
                expect(pub[0]).to.be.equal('U');
            });
    });

    it('Test Cluster', () => {
        return createCluster()
            .then((c: KeyPair) => {
                return c.getPublicKey();
            }).then((pub: string) => {
                expect(pub).to.be.a('string');
                expect(pub[0]).to.be.equal('C');
            });
    });

    it('Test Server', () => {
        return createServer()
            .then((s: KeyPair) => {
                return s.getPublicKey();
            }).then((pub: string) => {
                expect(pub).to.be.a('string');
                expect(pub[0]).to.be.equal('N');
            });
    });

    it('from public kp cannot get private keys', () => {
        let user: KeyPair;
        return createUser()
            .then((u: KeyPair) => {
                user = u;
                return user.getPublicKey();
            }).then((pubkey: string) => {
                return fromPublic(pubkey);
            }).then((kp: KeyPair) => {
                return kp.getPrivateKey()
            }).then((pk: string) => {
                assert.fail(pk, "", "public key was not expected");
            }).catch((error: Error) => {
                expect(error).to.be.instanceof(Error);
                let nerr : NKeysError = error as NKeysError;
                expect(nerr.code).to.be.equal(NKeysErrorCode.PublicKeyOnly);
            })
    });

    it('from public kp cannot get seed', () => {
        let user: KeyPair;
        return createUser()
            .then((u: KeyPair) => {
                user = u;
                return user.getPublicKey();
            }).then((pubkey: string) => {
                return fromPublic(pubkey);
            }).then((kp: KeyPair) => {
                return kp.getSeed()
            }).then((pk: string) => {
                assert.fail(pk, "", "seed was not expected");
            }).catch((error: Error) => {
                expect(error).to.be.instanceof(Error);
                let nerr : NKeysError = error as NKeysError;
                expect(nerr.code).to.be.equal(NKeysErrorCode.PublicKeyOnly);
            })
    });

    it('Test fromPublic() can verify', () => {
        let user: KeyPair;
        let pubUser1: KeyPair;
        let pubUser2: KeyPair;
        let data = Buffer.from("HelloWorld");

        return createUser()
            .then((u: KeyPair) => {
                user = u;
                return user.getPublicKey();
            }).then((pubKey: string) => {
                return Promise.all([
                    fromPublic(pubKey),
                    fromPublic(pubKey)]);
            }).then((kp: KeyPair[]) => {
                pubUser1 = kp[0];
                pubUser2 = kp[1];
                return Promise.all([
                    pubUser1.getPublicKey(),
                    pubUser2.getPublicKey()
                ]);
            }).then((keys: string[]) => {
                expect(keys[0]).to.equal(keys[1]);
                return user.sign(data);
            }).then((signature: Buffer) => {
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

    it('Test fromSeed', () => {
        let account: KeyPair;
        let data = Buffer.from("HelloWorld");
        let signature: Buffer;

        return createAccount()
            .then((a: KeyPair) => {
                account = a;
                return account.sign(data)
            }).then ((sig: Buffer) => {
                signature = sig;
                return account.getSeed();
            }).then((seed: string) => {
                expect(seed).to.be.a('string');
                expect(seed[0]).to.be.equal('S');
                expect(seed[1]).to.be.equal('A');

                return fromSeed(seed)
            }).then((a2: KeyPair) => {
                return a2.verify(data, signature);
            }).then((ok: boolean) => {
                expect(ok).to.be.true;
            })
    });

    it('should fail if key is empty', () => {
        return createPair(Prefix.User, Buffer.from([]))
            .then((bad: KeyPair) => {
                assert.fail(bad, "", "pair was not expected");
            })
            .catch((err: Error) => {
                expect(err).to.be.instanceof(Error);
            })
    });

    it('should fail with non public prefix', () => {
        return createPair(Prefix.Private)
            .then((bad: KeyPair) => {
                assert.fail(bad, "", "pair was not expected");
            })
            .catch((err: Error) => {
                expect(err).to.be.instanceof(Error);
            })
    });

    it('should fail getting keys on bad seed', () => {
        let kp = new KP("SEEDBAD");
        kp.getKeys()
            .then((sp: SignKeyPair) => {
                assert.fail(sp, "", "keys were not expected");
            })
            .catch((err: Error) => {
                expect(err).to.be.instanceof(Error);
                let nerr : NKeysError = err as NKeysError;
                expect(nerr.code).to.be.equal(NKeysErrorCode.InvalidChecksum);
            })
    });

    it('should fail getting public key on bad seed', () => {
        let kp = new KP("SEEDBAD");
        kp.getPublicKey()
            .then((pk: string) => {
                assert.fail(pk, "", "key was not expected");
            })
            .catch((err: Error) => {
                expect(err).to.be.instanceof(Error);
                let nerr : NKeysError = err as NKeysError;
                expect(nerr.code).to.be.equal(NKeysErrorCode.InvalidChecksum);
            })
    });

    it('should fail getting private key on bad seed', () => {
        let kp = new KP("SEEDBAD");
        kp.getPrivateKey()
            .then((pk: string) => {
                assert.fail(pk, "", "key was not expected");
            })
            .catch((err: Error) => {
                expect(err).to.be.instanceof(Error);
                let nerr : NKeysError = err as NKeysError;
                expect(nerr.code).to.be.equal(NKeysErrorCode.InvalidChecksum);
            })
    });

    it('should fail signing with bad seed', () => {
        let kp = new KP("SEEDBAD");
        kp.sign(Buffer.from([]))
            .then((sig: Buffer) => {
                assert.fail(sig, "", "signature was not expected");
            })
            .catch((err: Error) => {
                expect(err).to.be.instanceof(Error);
                let nerr : NKeysError = err as NKeysError;
                expect(nerr.code).to.be.equal(NKeysErrorCode.InvalidChecksum);
            })
    });

    function badKey(): Promise<string> {
        return new Promise((resolve,reject) => {
            createAccount()
                .then((a: KeyPair) => {
                    return a.getPublicKey();
                })
                .then((pk: string) => {
                    resolve(pk.slice(0, pk.length-2) + "00");
                })
                .catch((err: Error) => {
                    reject(err);
                });
            })
    }

    it('should reject decoding bad checksums', () => {
        badKey()
            .then((bpk: string) => {
            Codec.decode(bpk)
                .then((buf: Buffer) => {
                    assert.fail(buf, "", "decode was not expected");
                })
                .catch((err: Error) => {
                    expect(err).to.be.instanceof(Error);
                    let nerr : NKeysError = err as NKeysError;
                    expect(nerr.code).to.be.equal(NKeysErrorCode.InvalidEncoding);
                });
        })
    });

    it('should reject decoding expected byte with bad checksum', () => {
        badKey()
            .then((bpk: string) => {
                Codec.decodeExpectingPrefix(Prefix.User, bpk)
                    .then((buf: Buffer) => {
                        assert.fail(buf, "", "decode was not expected");
                    })
                    .catch((err: Error) => {
                        expect(err).to.be.instanceof(Error);
                        let nerr : NKeysError = err as NKeysError;
                        expect(nerr.code).to.be.equal(NKeysErrorCode.InvalidEncoding);
                    });
            })
    });

    it('should reject decoding expected bad prefix', () => {
        badKey()
            .then((bpk: string) => {
                Codec.decodeExpectingPrefix(3<<3, bpk)
                    .then((buf: Buffer) => {
                        assert.fail(buf, "", "decode was not expected");
                    })
                    .catch((err: Error) => {
                        expect(err).to.be.instanceof(Error);
                        let nerr : NKeysError = err as NKeysError;
                        expect(nerr.code).to.be.equal(NKeysErrorCode.InvalidPrefixByte);
                    });
            })
    });

    it('should reject decoding expected bad checksum', () => {
        badKey()
            .then((bpk: string) => {
                Codec.decodeExpectingPrefix(Prefix.Account, bpk)
                    .then((buf: Buffer) => {
                        assert.fail(buf, "", "decode was not expected");
                    })
                    .catch((err: Error) => {
                        expect(err).to.be.instanceof(Error);
                        let nerr : NKeysError = err as NKeysError;
                        expect(nerr.code).to.be.equal(NKeysErrorCode.InvalidEncoding);
                    });
            })
    });

    it('should reject decoding seed with bad checksum', () => {
        badKey()
            .then((bpk: string) => {
                Codec.decodeSeed(bpk)
                    .then((sd: SeedDecode) => {
                        assert.fail(sd, "", "decode was not expected");
                    })
                    .catch((err: Error) => {
                        expect(err).to.be.instanceof(Error);
                        let nerr : NKeysError = err as NKeysError;
                        expect(nerr.code).to.be.equal(NKeysErrorCode.InvalidEncoding);
                    });
            })
    });

    it('fromPublicKey should reject bad checksum', () => {
        badKey()
            .then((bpk: string) => {
                fromPublic(bpk)
                    .then((kp: KeyPair) => {
                        assert.fail(kp, "", "decode was not expected");
                    })
                    .catch((err: Error) => {
                        expect(err).to.be.instanceof(Error);
                        let nerr : NKeysError = err as NKeysError;
                        expect(nerr.code).to.be.equal(NKeysErrorCode.InvalidEncoding);
                    });
            })
    });

    function generateBadSeed(): Promise<string> {
        return new Promise((resolve) => {
            createAccount()
                .then((a: KeyPair) => {
                    return a.getSeed()
                }).then((seed: string) => {
                resolve(seed[0] + 'S' + seed.slice(2));
            });
        });
    }

    it('should reject decoding seed bad checksum', () => {
        createAccount()
            .then((a: KeyPair) => {
                return a.getPublicKey()
            })
            .then((bpk: string) => {
                Codec.decodeSeed(bpk)
                    .then((sd: SeedDecode) => {
                        assert.fail(sd, "", "decode was not expected");
                    })
                    .catch((err: Error) => {
                        expect(err).to.be.instanceof(Error);
                        let nerr : NKeysError = err as NKeysError;
                        expect(nerr.code).to.be.equal(NKeysErrorCode.InvalidSeed);
                    });
            })
    });


    it('should reject decoding bad seed prefix', () => {
        generateBadSeed()
            .then((seed: string) => {
                Codec.decodeSeed(seed)
                    .then((sd: SeedDecode) => {
                        assert.fail(sd, "", "decode was not expected");
                    })
                    .catch((err: Error) => {
                        expect(err).to.be.instanceof(Error);
                        let nerr : NKeysError = err as NKeysError;
                        expect(nerr.code).to.be.equal(NKeysErrorCode.InvalidChecksum);
                    });
            })
    });

    it('fromSeed should reject decoding bad seed prefix', () => {
        generateBadSeed()
            .then((seed: string) => {
                fromSeed(seed)
                    .then((kp: KeyPair) => {
                        assert.fail(kp, "", "decode was not expected");
                    })
                    .catch((err: Error) => {
                        expect(err).to.be.instanceof(Error);
                        let nerr : NKeysError = err as NKeysError;
                        expect(nerr.code).to.be.equal(NKeysErrorCode.InvalidChecksum);
                    });
            })
    });

    it('fromSeed should reject decoding bad public key', () => {
        generateBadSeed()
            .then((seed: string) => {
                fromPublic(seed)
                    .then((kp: KeyPair) => {
                        assert.fail(kp, "", "decode was not expected");
                    })
                    .catch((err: Error) => {
                        expect(err).to.be.instanceof(Error);
                        let nerr : NKeysError = err as NKeysError;
                        expect(nerr.code).to.be.equal(NKeysErrorCode.InvalidChecksum);
                    });
            })
    });
});
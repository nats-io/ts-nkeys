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

import test from "ava";
import {KP} from "../src/kp";
import {Codec} from "../src/codec";
import {
    createAccount,
    createCluster,
    createPair,
    createServer,
    createUser,
    fromPublic,
    fromSeed,
    KeyPair,
    NKeysErrorCode,
    Prefix
} from "../src/nkeys";
import ed25519 = require('tweetnacl');
import {PublicKey} from "../src/public";


test('Account', async (t) => {
    let account = await createAccount();
    t.truthy(account);

    let seed = await account.getSeed();
    t.is(typeof seed, 'string');
    t.is(seed[0], 'S');
    t.is(seed[1], 'A');

    let publicKey = await account.getPublicKey();
    t.is(typeof publicKey, 'string');
    t.is(publicKey[0], 'A');

    let privateKey = await account.getPrivateKey();
    t.is(typeof privateKey, 'string');
    t.is(privateKey[0], 'P');


    let data = Buffer.from("HelloWorld");
    let sig = await account.sign(data);
    t.is(sig.length, ed25519.sign.signatureLength);
    t.true(await account.verify(data, sig));

    let pk = await fromPublic(publicKey);
    t.true(await pk.verify(data, sig));

    let sk = await fromSeed(seed);
    t.true(await sk.verify(data, sig));
});

test('User', async (t) => {
    let user = await createUser();
    t.truthy(user);

    let seed = await user.getSeed();
    t.is(typeof seed, 'string');
    t.is(seed[0], 'S');
    t.is(seed[1], 'U');

    let publicKey = await user.getPublicKey();
    t.is(typeof publicKey, 'string');
    t.is(publicKey[0], 'U');

    let privateKey = await user.getPrivateKey();
    t.is(typeof privateKey, 'string');
    t.is(privateKey[0], 'P');


    let data = Buffer.from("HelloWorld");
    let sig = await user.sign(data);
    t.is(sig.length, ed25519.sign.signatureLength);
    t.true(await user.verify(data, sig));

    let pk = await fromPublic(publicKey);
    t.true(await pk.verify(data, sig));

    let sk = await fromSeed(seed);
    t.true(await sk.verify(data, sig));
});

test('Cluster', async (t) => {
    let cluster = await createCluster();
    t.truthy(cluster);

    let seed = await cluster.getSeed();
    t.is(typeof seed, 'string');
    t.is(seed[0], 'S');
    t.is(seed[1], 'C');

    let publicKey = await cluster.getPublicKey();
    t.is(typeof publicKey, 'string');
    t.is(publicKey[0], 'C');

    let privateKey = await cluster.getPrivateKey();
    t.is(typeof privateKey, 'string');
    t.is(privateKey[0], 'P');


    let data = Buffer.from("HelloWorld");
    let sig = await cluster.sign(data);
    t.is(sig.length, ed25519.sign.signatureLength);
    t.true(await cluster.verify(data, sig));

    let pk = await fromPublic(publicKey);
    t.true(await pk.verify(data, sig));

    let sk = await fromSeed(seed);
    t.true(await sk.verify(data, sig));
});

test('Server', async (t) => {
    let server = await createServer();
    t.truthy(server);

    let seed = await server.getSeed();
    t.is(typeof seed, 'string');
    t.is(seed[0], 'S');
    t.is(seed[1], 'N');

    let publicKey = await server.getPublicKey();
    t.is(typeof publicKey, 'string');
    t.is(publicKey[0], 'N');

    let privateKey = await server.getPrivateKey();
    t.is(typeof privateKey, 'string');
    t.is(privateKey[0], 'P');


    let data = Buffer.from("HelloWorld");
    let sig = await server.sign(data);
    t.is(sig.length, ed25519.sign.signatureLength);
    t.true(await server.verify(data, sig));

    let pk = await fromPublic(publicKey);
    t.true(await pk.verify(data, sig));

    let sk = await fromSeed(seed);
    t.true(await sk.verify(data, sig));
});


test('from public kp cannot get private keys', async(t) => {
    let user = await createUser();
    let pubkey = await user.getPublicKey();
    let fpk = await fromPublic(pubkey);
    await t.throwsAsync(async () => {
        await fpk.getPrivateKey();
    }, {code: NKeysErrorCode.PublicKeyOnly});
});

test('from public kp cannot get seed', async (t) => {
    let u = await createUser();
    let pk = await u.getPublicKey();
    let fpk = await fromPublic(pk);
    await t.throwsAsync(async () => {
        await fpk.getSeed();
    }, {code: NKeysErrorCode.PublicKeyOnly});
});

test('Test fromPublic() can verify', async (t) => {
    let user = await createUser();
    let pk = await user.getPublicKey();
    let fpk = await fromPublic(pk);
    let data = Buffer.from("HelloWorld");
    let signature = await user.sign(data);
    t.true(await fpk.verify(data, signature));
    t.true(await user.verify(data, signature));
});

test('Test fromSeed', async (t) => {
    let account = await createAccount();
    let data = Buffer.from("HelloWorld");
    let signature = await account.sign(data);
    t.true(await account.verify(data, signature));

    let seed = await account.getSeed();
    t.is(typeof seed, 'string');
    t.is(seed[0], 'S');
    t.is(seed[1], 'A');

    let fseed = await fromSeed(seed);
    t.true(await fseed.verify(data, signature));
});

test('should fail if key is empty', async (t) => {
    await t.throwsAsync(async () => {
        await createPair(Prefix.User, Buffer.from([]));
    }, {message: 'bad seed size'});
});

test('should fail with non public prefix', async (t) => {
    await t.throwsAsync(async () => {
        await createPair(Prefix.Private);
    }, {code: NKeysErrorCode.InvalidPrefixByte});
});

test('should fail getting keys on bad seed', async(t) => {
    await t.throwsAsync(async () => {
        let kp = new KP("SEEDBAD");
        await kp.getKeys();
    }, {code: NKeysErrorCode.InvalidChecksum});
});

test('should fail getting public key on bad seed', async(t) => {
    await t.throwsAsync(async () => {
        let kp = new KP("SEEDBAD");
        await kp.getPublicKey();
    }, {code: NKeysErrorCode.InvalidChecksum});
});

test('should fail getting private key on bad seed', async (t) => {
    await t.throwsAsync(async () => {
        let kp = new KP("SEEDBAD");
        await kp.getPrivateKey();
    }, {code: NKeysErrorCode.InvalidChecksum});
});

test('should fail signing with bad seed', async (t) => {
    await t.throwsAsync(async () => {
        let kp = new KP("SEEDBAD");
        await kp.sign(Buffer.from([]));
    }, {code: NKeysErrorCode.InvalidChecksum});
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

test('should reject decoding bad checksums', async (t) => {
    await t.throwsAsync(async () => {
        let bk = await badKey();
        await Codec.decode(bk);
    }, {code: NKeysErrorCode.InvalidEncoding});
});

test('should reject decoding expected byte with bad checksum', async(t) => {
    await t.throwsAsync(async () => {
        let bk = await badKey();
        await Codec.decodeExpectingPrefix(Prefix.User, bk);
    }, {code: NKeysErrorCode.InvalidEncoding});
});

test('should reject decoding expected bad prefix', async (t) => {
    await t.throwsAsync(async () => {
        let bk = await badKey();
        await Codec.decodeExpectingPrefix(3<<3, bk);
    }, {code: NKeysErrorCode.InvalidPrefixByte});
});

test('should reject decoding expected bad checksum', async(t) => {
    await t.throwsAsync(async () => {
        let bk = await badKey();
        await Codec.decodeExpectingPrefix(Prefix.Account, bk);
    }, {code: NKeysErrorCode.InvalidEncoding});
});

test('should reject decoding seed with bad checksum', async (t) => {
    await t.throwsAsync(async () => {
        let bk = await badKey();
        await Codec.decodeSeed(bk);
    }, {code: NKeysErrorCode.InvalidEncoding});
});

test('fromPublicKey should reject bad checksum', async(t) => {
    await t.throwsAsync(async () => {
        let bk = await badKey();
        await fromPublic(bk);
    }, {code: NKeysErrorCode.InvalidEncoding});
});


test('should reject decoding seed bad checksum', async(t) => {
    await t.throwsAsync(async () => {
        let a = await createAccount();
        let pk = await a.getPublicKey();
        await Codec.decodeSeed(pk);
    }, {code: NKeysErrorCode.InvalidSeed});
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

test('should reject decoding bad seed prefix', async (t) => {
    await t.throwsAsync(async () => {
        let s = await generateBadSeed();
        await Codec.decodeSeed(s);
    }, {code: NKeysErrorCode.InvalidChecksum});
});

test('fromSeed should reject decoding bad seed prefix', async(t) => {
    await t.throwsAsync(async () => {
        let s = await generateBadSeed();
        await fromSeed(s);
    }, {code: NKeysErrorCode.InvalidChecksum});
});

test('fromSeed should reject decoding bad public key', async (t) => {
    await t.throwsAsync(async () => {
        let s = await generateBadSeed();
        await fromPublic(s);
    }, {code: NKeysErrorCode.InvalidChecksum});
});

test('public key cannot sign', async (t) => {
    await t.throwsAsync(async () => {
        let a = await createAccount();
        let pks = await a.getPublicKey();
        let pk = new PublicKey(pks);
        let pks2 = await pk.getPublicKey();
        t.is(pks, pks2);
        await pk.sign(Buffer.from(""))
    }, {code: NKeysErrorCode.CannotSign});
});

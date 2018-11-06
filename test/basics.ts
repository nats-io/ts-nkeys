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
    createCluster, createOperator,
    createPair,
    createServer,
    createUser,
    fromPublic,
    fromSeed,
    NKeysErrorCode,
    Prefix, Prefixes
} from "../src/nkeys";
import ed25519 = require('tweetnacl');


test('Account', (t) => {
    let account = createAccount();
    t.truthy(account);

    let seed = account.getSeed();
    t.true(Buffer.isBuffer(seed));
    t.is(seed[0], 'S'.charCodeAt(0));
    t.is(seed[1], 'A'.charCodeAt(0));

    let publicKey = account.getPublicKey();
    t.true(Buffer.isBuffer(publicKey));
    t.is(publicKey[0], 'A'.charCodeAt(0));

    let privateKey = account.getPrivateKey();
    t.true(Buffer.isBuffer(privateKey));
    t.is(privateKey[0], 'P'.charCodeAt(0));

    let data = Buffer.from("HelloWorld");
    let sig = account.sign(data);
    t.is(sig.length, ed25519.sign.signatureLength);
    t.true(account.verify(data, sig));
    t.true(Buffer.isBuffer(sig));

    let sk = fromSeed(seed);
    t.true(sk.verify(data, sig));

    let pk = fromPublic(publicKey);
    t.is(pk.getPublicKey(), publicKey);

    t.throws(pk.getPrivateKey);
    t.true(pk.verify(data, sig));
});

test('User', (t) => {
    let user = createUser();
    t.truthy(user);

    let seed = user.getSeed();
    t.true(Buffer.isBuffer(seed));
    t.is(seed[0], 'S'.charCodeAt(0));
    t.is(seed[1], 'U'.charCodeAt(0));

    let publicKey = user.getPublicKey();
    t.true(Buffer.isBuffer(publicKey));
    t.is(publicKey[0], 'U'.charCodeAt(0));

    let privateKey = user.getPrivateKey();
    t.true(Buffer.isBuffer(privateKey));
    t.is(privateKey[0], 'P'.charCodeAt(0));


    let data = Buffer.from("HelloWorld");
    let sig = user.sign(data);
    t.is(sig.length, ed25519.sign.signatureLength);
    t.true(user.verify(data, sig));

    let pk = fromPublic(publicKey);
    t.true(pk.verify(data, sig));
    t.throws(pk.getPrivateKey);

    let sk = fromSeed(seed);
    t.true(sk.verify(data, sig));
});

test('Cluster', (t) => {
    let cluster = createCluster();
    t.truthy(cluster);

    let seed = cluster.getSeed();
    t.true(Buffer.isBuffer(seed));
    t.is(seed[0], 'S'.charCodeAt(0));
    t.is(seed[1], 'C'.charCodeAt(0));

    let publicKey = cluster.getPublicKey();
    t.true(Buffer.isBuffer(publicKey));
    t.is(publicKey[0], 'C'.charCodeAt(0));

    let privateKey = cluster.getPrivateKey();
    t.true(Buffer.isBuffer(privateKey));
    t.is(privateKey[0], 'P'.charCodeAt(0));


    let data = Buffer.from("HelloWorld");
    let sig = cluster.sign(data);
    t.is(sig.length, ed25519.sign.signatureLength);
    t.true(cluster.verify(data, sig));

    let pk = fromPublic(publicKey);
    t.true(pk.verify(data, sig));
    t.throws(pk.getPrivateKey);

    let sk = fromSeed(seed);
    t.true(sk.verify(data, sig));
});

test('Operator', (t) => {
    let operator = createOperator();
    t.truthy(operator);

    let seed = operator.getSeed();
    t.true(Buffer.isBuffer(seed));
    t.is(seed[0], 'S'.charCodeAt(0));
    t.is(seed[1], 'O'.charCodeAt(0));

    let publicKey = operator.getPublicKey();
    t.true(Buffer.isBuffer(publicKey));
    t.is(publicKey[0], 'O'.charCodeAt(0));

    let privateKey = operator.getPrivateKey();
    t.true(Buffer.isBuffer(privateKey));
    t.is(privateKey[0], 'P'.charCodeAt(0));

    let data = Buffer.from("HelloWorld");
    let sig = operator.sign(data);
    t.is(sig.length, ed25519.sign.signatureLength);
    t.true(operator.verify(data, sig));

    let pk = fromPublic(publicKey);
    t.true(pk.verify(data, sig));
    t.throws(pk.getPrivateKey);

    let sk = fromSeed(seed);
    t.true(sk.verify(data, sig));
});

test('Server', (t) => {
    let server = createServer();
    t.truthy(server);
    let seed = server.getSeed();
    t.true(Buffer.isBuffer(seed));
    t.is(seed[0], 'S'.charCodeAt(0));
    t.is(seed[1], 'N'.charCodeAt(0));

    let publicKey = server.getPublicKey();
    t.true(Buffer.isBuffer(publicKey));
    t.is(publicKey[0], 'N'.charCodeAt(0));

    let privateKey = server.getPrivateKey();
    t.true(Buffer.isBuffer(privateKey));
    t.is(privateKey[0], 'P'.charCodeAt(0));


    let data = Buffer.from("HelloWorld");
    let sig = server.sign(data);
    t.is(sig.length, ed25519.sign.signatureLength);
    t.true(server.verify(data, sig));

    let pk = fromPublic(publicKey);
    t.true(pk.verify(data, sig));
    t.throws(pk.getPrivateKey);

    let sk = fromSeed(seed);
    t.true(sk.verify(data, sig));
});


test('from public kp cannot get private keys', (t) => {
    let user = createUser();
    let pubkey = user.getPublicKey();
    let fpk = fromPublic(pubkey);
    t.throws(() => {
        fpk.getPrivateKey();
    }, {code: NKeysErrorCode.PublicKeyOnly});
});

test('from public kp cannot get seed', (t) => {
    let u = createUser();
    let pk = u.getPublicKey();
    let fpk = fromPublic(pk);
    t.throws( () => {
        fpk.getSeed();
    }, {code: NKeysErrorCode.PublicKeyOnly});
});

test('Test fromPublic() can verify', (t) => {
    let user = createUser();
    let pk = user.getPublicKey();
    let fpk = fromPublic(pk);
    let data = Buffer.from("HelloWorld");
    let signature = user.sign(data);
    t.true(fpk.verify(data, signature));
    t.true(user.verify(data, signature));
});

test('Test fromSeed', (t) => {
    let account = createAccount();
    let data = Buffer.from("HelloWorld");
    let signature = account.sign(data);
    t.true(account.verify(data, signature));

    let seed = account.getSeed();
    t.true(Buffer.isBuffer(seed));
    t.is(seed[0], 'S'.charCodeAt(0));
    t.is(seed[1], 'A'.charCodeAt(0));

    let fseed = fromSeed(seed);
    t.true(fseed.verify(data, signature));
});

test('should fail with non public prefix', (t) => {
    t.throws(() => {
        createPair(Prefix.Private);
    }, {code: NKeysErrorCode.InvalidPrefixByte});
});

test('should fail getting public key on bad seed', (t) => {
    t.throws(() => {
        let kp = new KP(Buffer.from("SEEDBAD"));
        kp.getPublicKey();
    }, {code: NKeysErrorCode.InvalidChecksum});
});

test('should fail getting private key on bad seed',  (t) => {
    t.throws(() => {
        let kp = new KP(Buffer.from("SEEDBAD"));
        kp.getPrivateKey();
    }, {code: NKeysErrorCode.InvalidChecksum});
});

test('should fail signing with bad seed', (t) => {
    t.throws(() => {
        let kp = new KP(Buffer.from("SEEDBAD"));
        kp.sign(Buffer.from([]));
    }, {code: NKeysErrorCode.InvalidChecksum});
});

function badKey(): Buffer {
        let a = createAccount();
        let pk = a.getPublicKey();
        pk[pk.byteLength-1] = "0".charCodeAt(0);
        pk[pk.byteLength-2] = "0".charCodeAt(0);
        return pk;
}

test('should reject decoding bad checksums', (t) => {
    t.throws(() => {
        let bk = badKey();
        Codec._decode(bk);
    }, {code: NKeysErrorCode.InvalidEncoding});
});

test('should reject decoding expected byte with bad checksum', (t) => {
    t.throws(() => {
        let bk = badKey();
        Codec.decode(Prefix.User, bk);
    }, {code: NKeysErrorCode.InvalidEncoding});
});

test('should reject decoding expected bad prefix', (t) => {
    t.throws(() => {
        let bk = badKey();
        Codec.decode(3<<3, bk);
    }, {code: NKeysErrorCode.InvalidPrefixByte});
});

test('should reject decoding expected bad checksum', (t) => {
    t.throws(() => {
        let bk = badKey();
        Codec.decode(Prefix.Account, bk);
    }, {code: NKeysErrorCode.InvalidEncoding});
});

test('should reject decoding seed with bad checksum', (t) => {
    t.throws(() => {
        let bk = badKey();
        Codec.decodeSeed(bk);
    }, {code: NKeysErrorCode.InvalidEncoding});
});

test('fromPublicKey should reject bad checksum', (t) => {
    t.throws(() => {
        let bk = badKey();
        fromPublic(bk);
    }, {code: NKeysErrorCode.InvalidEncoding});
});


test('should reject decoding seed bad checksum', (t) => {
    t.throws(() => {
        let a = createAccount();
        let pk = a.getPublicKey();
        Codec.decodeSeed(pk);
    }, {code: NKeysErrorCode.InvalidSeed});
});

function generateBadSeed(): Buffer {
        let a = createAccount();
        let seed = a.getSeed();
        seed[1] = 'S'.charCodeAt(0);
        return seed;
}

test('should reject decoding bad seed prefix', (t) => {
    t.throws( () => {
        let s = generateBadSeed();
        Codec.decodeSeed(s);
    }, {code: NKeysErrorCode.InvalidChecksum});
});

test('fromSeed should reject decoding bad seed prefix', (t) => {
    t.throws(() => {
        let s = generateBadSeed();
        fromSeed(s);
    }, {code: NKeysErrorCode.InvalidChecksum});
});

test('fromSeed should reject decoding bad public key', (t) => {
    t.throws(() => {
        let s = generateBadSeed();
        fromPublic(s);
    }, {code: NKeysErrorCode.InvalidChecksum});
});

test('public key cannot sign', (t) => {
    t.throws(() => {
        let a = createAccount();
        let pks = a.getPublicKey();
        let pk = fromPublic(pks);
        let pks2 = pk.getPublicKey();
        t.is(pks, pks2);
        pk.sign(Buffer.from(""))
    }, {code: NKeysErrorCode.CannotSign});
});

test('from public rejects non-public keys', (t) => {
    t.throws(() => {
        let a = createAccount();
        let pks = a.getSeed();
        fromPublic(pks);
    }, {code: NKeysErrorCode.InvalidPublicKey});
});


test('test valid prefixes', (t) => {
    let valid = ['S', 'P', 'O', 'N', 'C', 'A', 'U'];
    valid.forEach((v:string) => {
        t.true(Prefixes.startsWithValidPrefix(v))
    });
    let b32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=";
    b32.split('').forEach((c: string) => {
        let ok = valid.indexOf(c) !== -1;
        if (ok) {
            t.true(Prefixes.startsWithValidPrefix(c));
        } else {
            t.false(Prefixes.startsWithValidPrefix(c));
        }
    })


});

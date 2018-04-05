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
import {Prefix} from "../src/prefix";
import {TokenCodec} from "../src/strkey";
import {KP, KeyPair} from "../src/keypair";
import ed25519 = require('tweetnacl')
import {NKeysError, NKeysErrorCode} from "../src/errors";


describe('Test KeyPair', ()=> {
    it('Test Accounts', () => {
        let account = KP.createAccount() as KeyPair;
        expect(account).to.not.be.null;
        let seed = account.getSeed();
        expect(seed).to.be.string;
        //@ts-ignore
        expect(seed[0]).to.be.equal('S');
        //@ts-ignore
        expect(seed[1]).to.be.equal('A');

        //@ts-ignore
        let raw = TokenCodec.decodeAs(Prefix.Seed, seed);
        expect(raw).to.be.an.instanceof(Buffer);

        let pub = account.getPublicKey();
        expect(pub).to.not.be.instanceof(Error);
        //@ts-ignore
        expect(pub[0]).to.be.equal('A');

        let secret = account.getPrivateKey();
        expect(secret).to.not.be.instanceof(Error);
        //@ts-ignore
        expect(secret[0]).to.be.equal('P');

        let data = new Buffer("HelloWorld");
        let sig = account.sign(data);
        expect(sig).to.not.be.instanceof(Error);
        expect(sig).length(ed25519.sign.signatureLength);

        //@ts-ignore
        let ok = account.verify(data, sig);
        expect(ok).to.be.true;
    });

    it('Test User', () => {
        let user = KP.createUser() as KeyPair;
        expect(user).to.not.be.null;

        let pub = user.getPublicKey();
        expect(pub).to.not.be.instanceof(Error);
        //@ts-ignore
        expect(pub[0]).to.be.equal('U');
    });

    it('Test Cluster', () => {
        let cluster = KP.createCluster() as KeyPair;
        expect(cluster).to.not.be.null;

        let pub = cluster.getPublicKey();
        expect(pub).to.not.be.instanceof(Error);
        //@ts-ignore
        expect(pub[0]).to.be.equal('C');
    });


    it('Test Server', () => {
        let server = KP.createServer() as KeyPair;
        expect(server).to.not.be.null;

        let pub = server.getPublicKey();
        expect(pub).to.not.be.instanceof(Error);
        //@ts-ignore
        expect(pub[0]).to.be.equal('N');
    });

    it('Test From Public', () => {
        let user = KP.createUser() as KeyPair;
        expect(user).to.not.be.null;

        let pk = user.getPublicKey();
        expect(pk).to.not.be.instanceof(Error);

        //@ts-ignore
        let pu = KP.fromPublic(pk) as KeyPair;
        expect(pu).to.not.be.instanceof(Error);

        let puk = pu.getPublicKey();
        expect(puk).to.not.be.instanceof(Error);
        expect(puk).to.be.equal(pk);

        expect(pu.getPrivateKey()).to.be.instanceof(Error);
        expect(pu.getSeed()).to.be.instanceof(Error);

        let data = new Buffer("HelloWorld");
        let err = pu.sign(data) as NKeysError;
        expect(err).to.be.instanceof(Error);
        expect(err.code).to.be.equal(NKeysErrorCode.CannotSign);

        let sig = user.sign(data);
        expect(sig).to.not.be.instanceof(Error);
        expect(sig).length(ed25519.sign.signatureLength);
        //@ts-ignore
        expect(pu.verify(data, sig)).to.be.true;

        let bu = new KP("USERBAD");
        //@ts-ignore
        expect(() => bu.verify(data, sig)).to.throw;
    });
});
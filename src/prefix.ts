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
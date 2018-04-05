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

export function dump(buf: Buffer, msg?: string): void {
    if (msg) {
        console.log(msg);
    }
    let a: string[] = [];
    for (let i = 0; i < buf.byteLength; i++) {
        if (i % 8 === 0) {
            a.push('\n');
        }
        let v = buf[i].toString(16);
        if (v.length === 1) {
            v = '0' + v;
        }
        a.push(v);
    }
    console.log(a.join('  '));
}

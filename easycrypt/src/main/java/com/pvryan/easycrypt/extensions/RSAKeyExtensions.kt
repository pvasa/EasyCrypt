/*
 * Copyright 2018 Priyank Vasa
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

package com.pvryan.easycrypt.extensions

import java.security.interfaces.RSAKey

@PublishedApi
internal fun RSAKey.size(): Int = modulus.bitLength()

@PublishedApi
internal fun RSAKey.allowedInputSize(): Int {
    val keyLength = size().toDouble()
    val hashOutputLength = 256
    return (Math.floor(keyLength / 8)
            - (2 * (hashOutputLength / 8)) - 2).toInt() // OAEPwithSHA-256 padding
    //return (Math.floor(keyLength / 8) - 11).toInt() // PKCS#1 padding
}

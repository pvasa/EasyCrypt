/**
 * Copyright 2017 Priyank Vasa
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

import android.util.Base64
import com.pvryan.easycrypt.ECrypt
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

private val HEX_CHARS = "0123456789ABCDEF".toCharArray()
fun ByteArray.asString(): String = this.toString(Charsets.UTF_8)
fun ByteArray.toBase64(): ByteArray = Base64.encode(this, Base64.DEFAULT)
fun ByteArray.fromBase64(): ByteArray = Base64.decode(this, Base64.DEFAULT)
fun ByteArray.asHexString(): String {
    val result = StringBuffer()
    forEach {
        val octet = it.toInt()
        val firstIndex = (octet and 0xF0).ushr(4)
        val secondIndex = octet and 0x0F
        result.append(HEX_CHARS[firstIndex])
        result.append(HEX_CHARS[secondIndex])
    }
    return result.toString()
}

fun String.asByteArray(): ByteArray = this.toByteArray(Charsets.UTF_8)
fun String.toBase64(): String = this.asByteArray().toBase64().asString()
fun String.fromBase64(): String = this.asByteArray().fromBase64().asString()

fun ECrypt.getKey(password: String = String(), salt: ByteArray): SecretKeySpec {

    val pbeKeySpec: PBEKeySpec = PBEKeySpec(
            password.toCharArray(), salt, ITERATIONS, KEY_BITS_LENGTH)

    val keyFactory: SecretKeyFactory =
            SecretKeyFactory.getInstance(SECRET_KEY_FAC_ALGORITHM)

    val keyBytes: ByteArray = keyFactory.generateSecret(pbeKeySpec).encoded
    val keySpec = SecretKeySpec(keyBytes, SECRET_KEY_SPEC_ALGORITHM)

    return keySpec
}
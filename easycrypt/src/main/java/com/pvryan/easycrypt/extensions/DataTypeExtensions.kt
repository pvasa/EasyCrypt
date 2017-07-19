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
import java.util.regex.Pattern

fun ByteArray.toBase64(): ByteArray = Base64.encode(this, Base64.URL_SAFE)
fun ByteArray.toBase64String(): String = Base64.encodeToString(this, Base64.URL_SAFE)

@Throws(IllegalArgumentException::class)
fun ByteArray.fromBase64(): ByteArray = Base64.decode(this, Base64.URL_SAFE)

fun ByteArray.asString(): String = this.toString(Charsets.UTF_8)

private val HEX_CHARS = "0123456789ABCDEF".toCharArray()
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

val pHex: Pattern = Pattern.compile("[0-9a-fA-F]+")
fun String.isValidHex(): Boolean = (this.length % 2 == 0 && pHex.matcher(this).matches())

@Throws(IllegalArgumentException::class)
fun String.hexToByteArray(): ByteArray {
    val trimmed = this.replace(" ", "")
    if (!trimmed.isValidHex()) throw IllegalArgumentException("Invalid hex string.")
    val data = ByteArray(trimmed.length / 2)
    var i = 0
    while (i < trimmed.length) {
        data[i / 2] = ((Character.digit(trimmed[i], 16) shl 4) +
                Character.digit(trimmed[i + 1], 16)).toByte()
        i += 2
    }
    return data
}

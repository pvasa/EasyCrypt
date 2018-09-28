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
@file:Suppress("unused")

package com.pvryan.easycryptsample.extensions

import android.util.Base64
import java.security.interfaces.RSAKey
import java.util.regex.Pattern

fun ByteArray.toBase64String(): String = Base64.encodeToString(this, Base64.URL_SAFE)
fun ByteArray.toBase64(): ByteArray = Base64.encode(this, Base64.URL_SAFE)
fun ByteArray.asString(): String = toString(Charsets.UTF_8)

private val HEX_CHARS = charArrayOf('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F')
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

fun String.toNumber(default: Int): Int =
        try {
            Integer.valueOf(this)
        } catch (e: NumberFormatException) {
            default
        }

@Throws(IllegalArgumentException::class)
fun String.asByteArray(): ByteArray = toByteArray(Charsets.UTF_8)

fun String.fromBase64(): ByteArray = Base64.decode(asByteArray(), Base64.URL_SAFE)

private val pHex: Pattern = Pattern.compile("[0-9a-fA-F]+")
fun String.isValidHex(): Boolean = (length % 2 == 0 && pHex.matcher(this).matches())

@Throws(IllegalArgumentException::class)
fun String.hexToByteArray(): ByteArray {
    val trimmed = replace(" ", "")
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

fun RSAKey.size(): Int = modulus.bitLength()
fun RSAKey.allowedInputSize(): Int {
    val keyLength = size().toDouble()
    val hashOutputLength = 256
    return (Math.floor(keyLength / 8)
            - (2 * (hashOutputLength / 8)) - 2).toInt() // OAEPwithSHA-256 padding
    //return (Math.floor(keyLength / 8) - 11).toInt() // PKCS#1 padding
}

fun Long.Companion.sigNum(n: Long): Int = (n shr 63 or (-n).ushr(63)).toInt()

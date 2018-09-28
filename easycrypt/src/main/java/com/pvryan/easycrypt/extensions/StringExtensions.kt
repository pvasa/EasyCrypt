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

import android.util.Base64
import java.util.regex.Pattern

@Throws(IllegalArgumentException::class)
@PublishedApi
internal fun String.asByteArray(): ByteArray = toByteArray(Charsets.UTF_8)

@Throws(IllegalArgumentException::class)
@PublishedApi
internal fun String.fromBase64(): ByteArray = Base64.decode(asByteArray(), Base64.URL_SAFE)

private val pHex: Pattern = Pattern.compile("[0-9a-fA-F]+")
internal fun String.isValidHex(): Boolean = (length % 2 == 0 && pHex.matcher(this).matches())

@Throws(IllegalArgumentException::class)
internal fun String.hexToByteArray(): ByteArray {
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

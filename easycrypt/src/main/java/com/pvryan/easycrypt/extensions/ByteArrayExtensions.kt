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
import com.pvryan.easycrypt.Constants
import com.pvryan.easycrypt.ECResultListener
import timber.log.Timber
import java.io.File
import java.io.IOException
import java.security.SecureRandom

private val HEX_CHARS = "0123456789ABCDEF".toCharArray()

internal val random = SecureRandom()

fun ByteArray.toBase64String(): String = Base64.encodeToString(this, Base64.URL_SAFE)

fun ByteArray.toBase64(): ByteArray = Base64.encode(this, Base64.URL_SAFE)

fun ByteArray.asString(): String = toString(Charsets.UTF_8)

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

@PublishedApi
internal inline fun <reified T> ByteArray.handleSuccess(
        erl: ECResultListener<T>,
        outputFile: File,
        asBase64String: Boolean
) {
    if (outputFile.absolutePath != Constants.DEF_ENCRYPTED_FILE_PATH
            && outputFile.absolutePath != Constants.DEF_DECRYPTED_FILE_PATH) {

        try {
            outputFile.outputStream().use {
                if (asBase64String) it.write(toBase64())
                else it.write(this)
                it.flush()
            }
            erl.onSuccess?.invoke(outputFile as T)
        } catch (e: IOException) {
            Timber.d(e)
            erl.onFailure?.invoke(Constants.ERR_CANNOT_WRITE, e)
        }

    } else if (asBase64String) erl.onSuccess?.invoke(toBase64String() as T)
    else erl.onSuccess?.invoke(asString() as T)
}

@PublishedApi
internal fun ByteArray.generateRandom() = apply {
    random.nextBytes(this)
}

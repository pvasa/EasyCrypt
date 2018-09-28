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
package com.pvryan.easycrypt.hash

import com.pvryan.easycrypt.Constants
import com.pvryan.easycrypt.ECResultListener
import com.pvryan.easycrypt.extensions.asByteArray
import com.pvryan.easycrypt.extensions.asHexString
import kotlinx.coroutines.experimental.CoroutineStart
import kotlinx.coroutines.experimental.Dispatchers
import kotlinx.coroutines.experimental.GlobalScope
import kotlinx.coroutines.experimental.launch
import org.jetbrains.annotations.NotNull
import timber.log.Timber
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStream
import java.security.InvalidParameterException
import java.security.MessageDigest

class ECHash {

    /**
     * Decrypts the input data using AES algorithm in CBC mode with PKCS5Padding padding
     * and posts response to [ECResultListener.onSuccess] if successful or
     * posts error to [ECResultListener.onFailure] if failed.
     * Hashing progress is posted to [ECResultListener.onProgress].
     * Result is either returned as a Hex string or Hex string returned in [outputFile] if provided.
     *
     * @param input input data to be hashed. It can be of type
     * [String], [CharSequence], [ByteArray], [InputStream], or [File]
     * @param outputFile optional output file. If provided, result will be written to this file
     *
     * @exception NoSuchFileException if input is a File which does not exists or is a Directory
     * @exception InvalidParameterException if input data type is not supported
     * @exception IOException if cannot read or write to a file
     * @exception FileAlreadyExistsException if output file is provided and already exists
     */
    @JvmOverloads
    inline fun <reified T> calculate(
            @NotNull input: Any,
            @NotNull algorithm: ECHashAlgorithms = ECHashAlgorithms.SHA_512,
            @NotNull outputFile: File = File(Constants.DEF_HASH_FILE_PATH)
    ): ECResultListener<T> {

        val erl = ECResultListener<T>()

        val buffer = ByteArray(8192)

        val parsedInput: Any = when (input) {

            is String -> input.asByteArray().inputStream()
            is CharSequence -> input.toString().asByteArray().inputStream()
            is ByteArray -> input
            is File -> input.inputStream()
            is InputStream -> if (input.available() <= buffer.size) input.readBytes() else input
            else -> {
                erl.onFailure?.invoke(Constants.ERR_INPUT_TYPE_NOT_SUPPORTED, InvalidParameterException())
                return erl
            }
        }

        GlobalScope.launch(Dispatchers.Default, CoroutineStart.DEFAULT, null) {

            val digest: MessageDigest = MessageDigest.getInstance(algorithm.value)

            when (parsedInput) {

                is ByteArray -> {
                    val hash = digest.digest(parsedInput).asHexString()
                    if (outputFile.absolutePath != Constants.DEF_HASH_FILE_PATH) {
                        outputFile.outputStream().use {
                            it.write(hash.asByteArray())
                            it.flush()
                        }
                        erl.onSuccess?.invoke(outputFile as T)
                    } else {
                        erl.onSuccess?.invoke(hash as T)
                    }
                }

                is InputStream -> {

                    try {
                        val size = (parsedInput as? FileInputStream)?.channel?.size() ?: -1
                        var bytesCopied: Long = 0
                        var read = parsedInput.read(buffer)
                        while (read > -1) {
                            digest.update(buffer, 0, read)
                            bytesCopied += read
                            erl.onProgress?.invoke(read, bytesCopied, size)
                            read = parsedInput.read(buffer)
                        }

                        val hash = digest.digest().asHexString()

                        if (outputFile.absolutePath != Constants.DEF_HASH_FILE_PATH) {
                            outputFile.outputStream().use {
                                it.write(hash.asByteArray())
                                it.flush()
                            }
                            erl.onSuccess?.invoke(outputFile as T)
                        } else {
                            erl.onSuccess?.invoke(hash as T)
                        }

                    } catch (e: IOException) {
                        Timber.d(e)
                        erl.onFailure?.invoke(Constants.ERR_CANNOT_READ, e)
                    } finally {
                        parsedInput.close()
                    }
                }

                else -> erl.onFailure?.invoke(Constants.ERR_INPUT_TYPE_NOT_SUPPORTED, InvalidParameterException())
            }
        }
        return erl
    }
}

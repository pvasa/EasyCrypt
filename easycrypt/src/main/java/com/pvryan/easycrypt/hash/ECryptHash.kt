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

package com.pvryan.easycrypt.hash

import com.pvryan.easycrypt.Constants
import com.pvryan.easycrypt.ECryptResultListener
import com.pvryan.easycrypt.extensions.asByteArray
import com.pvryan.easycrypt.extensions.asHexString
import org.jetbrains.anko.doAsync
import org.jetbrains.annotations.NotNull
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.security.InvalidParameterException
import java.security.MessageDigest

class ECryptHash {

    /**
     * Decrypts the input data using AES algorithm in CBC mode with PKCS5Padding padding
     * and posts response to [ECryptResultListener.onSuccess] if successful or
     * posts error to [ECryptResultListener.onFailure] if failed.
     * Hashing progress is posted to [ECryptResultListener.onProgress].
     * Result is either returned as a Hex string or Hex string returned in [outputFile] if provided.
     *
     * @param input input data to be hashed. It can be of type
     * [String], [CharSequence], [ByteArray], [InputStream], or [File]
     * @param erl listener interface of type ResultListener where result and progress will be posted
     * @param outputFile optional output file. If provided, result will be written to this file
     *
     * @exception NoSuchFileException if input is a File which does not exists or is a Directory
     * @exception InvalidParameterException if input data type is not supported
     * @exception IOException if cannot read or write to a file
     * @exception FileAlreadyExistsException if output file is provided and already exists
     */
    @JvmOverloads
    fun <T> calculate(@NotNull input: T,
                      @NotNull algorithm: ECryptHashAlgorithms = ECryptHashAlgorithms.SHA_512,
                      @NotNull erl: ECryptResultListener,
                      @NotNull outputFile: File = File(Constants.DEF_HASH_FILE_PATH)) {
        doAsync {

            val digest: MessageDigest = MessageDigest.getInstance(algorithm.value)

            when (input) {

                is String -> {
                    calculate(input.asByteArray().inputStream(), algorithm, erl, outputFile)
                }

                is CharSequence -> {
                    calculate(input.toString().asByteArray().inputStream(),
                            algorithm, erl, outputFile)
                }

                is File -> {
                    calculate(input.inputStream(), algorithm, erl, outputFile)
                }

                is ByteArray -> {
                    val hash = digest.digest(input).asHexString()
                    if (outputFile.absolutePath != Constants.DEF_HASH_FILE_PATH) {
                        outputFile.outputStream().use {
                            it.write(hash.asByteArray())
                            it.flush()
                        }
                        erl.onSuccess(outputFile)
                    } else {
                        erl.onSuccess(hash)
                    }
                }

                is InputStream -> {

                    val buffer = ByteArray(8192)

                    if (input.available() <= buffer.size) {
                        calculate(input.readBytes(), algorithm, erl, outputFile)
                        return@doAsync
                    }

                    try {

                        var bytesCopied: Long = 0
                        var read = input.read(buffer)
                        while (read > -1) {
                            digest.update(buffer, 0, read)
                            bytesCopied += read
                            erl.onProgress(read, bytesCopied)
                            read = input.read(buffer)
                        }

                        val hash = digest.digest().asHexString()

                        if (outputFile.absolutePath != Constants.DEF_HASH_FILE_PATH) {
                            outputFile.outputStream().use {
                                it.write(hash.asByteArray())
                                it.flush()
                            }
                            erl.onSuccess(outputFile)
                        } else {
                            erl.onSuccess(hash)
                        }

                    } catch (e: IOException) {
                        erl.onFailure(Constants.MSG_CANNOT_READ, e)
                    } finally {
                        input.close()
                    }
                }

                else -> erl.onFailure(Constants.MSG_INPUT_TYPE_NOT_SUPPORTED, InvalidParameterException())
            }
        }
    }
}
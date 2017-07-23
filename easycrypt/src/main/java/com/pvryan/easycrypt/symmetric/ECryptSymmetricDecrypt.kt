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

package com.pvryan.easycrypt.symmetric

import com.pvryan.easycrypt.ECryptResultListener
import com.pvryan.easycrypt.extensions.asString
import com.pvryan.easycrypt.extensions.fromBase64
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.security.InvalidParameterException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.IllegalBlockSizeException
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.system.exitProcess

@Suppress("UNCHECKED_CAST")
internal class ECryptSymmetricDecrypt<out T>
(input: T,
 password: String,
 cipher: Cipher,
 getKey: (password: String, salt: ByteArray) -> SecretKeySpec,
 erl: ECryptResultListener,
 outputFile: File) : Constants() {

    init {

        val IV_BYTES_LENGTH = cipher.blockSize

        when (input) {

            is ByteArray -> {

                val decodedBytes: ByteArray = try {
                    input.fromBase64()
                } catch (e: IllegalArgumentException) {
                    erl.onFailure(MSG_INVALID_INPUT_DATA, e)
                    byteArrayOf()
                    exitProcess(1)
                }

                decodedBytes.inputStream().use {

                    val IV = ByteArray(IV_BYTES_LENGTH)
                    val salt = ByteArray(SALT_BYTES_LENGTH)

                    if (IV_BYTES_LENGTH != it.read(IV) || SALT_BYTES_LENGTH != it.read(salt)) {
                        erl.onFailure(MSG_INVALID_INPUT_DATA, BadPaddingException())
                        exitProcess(1)
                    }

                    val ivParams = IvParameterSpec(IV)
                    val key = getKey(password, salt)

                    try {
                        cipher.init(Cipher.DECRYPT_MODE, key, ivParams)

                        val secureBytes = it.readBytes()
                        val plainBytes = cipher.doFinal(secureBytes)

                        if (outputFile.absolutePath != DEF_DECRYPTED_FILE_PATH) {
                            outputFile.outputStream().use {
                                it.write(plainBytes)
                                it.flush()
                            }
                            erl.onSuccess(outputFile as T)
                        } else {
                            erl.onSuccess(plainBytes.asString() as T)
                        }
                    } catch (e: BadPaddingException) {
                        erl.onFailure(MSG_INVALID_INPUT_DATA, e)
                    } catch (e: IllegalBlockSizeException) {
                        erl.onFailure(MSG_INVALID_INPUT_DATA, e)
                    }
                }
            }

            is InputStream -> {

                if (outputFile.exists()) {
                    if (outputFile.absolutePath != DEF_DECRYPTED_FILE_PATH) {
                        erl.onFailure(MSG_OUTPUT_FILE_EXISTS,
                                FileAlreadyExistsException(outputFile))
                        exitProcess(1)
                    }
                    outputFile.delete()
                }
                outputFile.createNewFile()

                var cis: CipherInputStream? = null
                val fos = outputFile.outputStream()

                val iv = ByteArray(IV_BYTES_LENGTH)
                val salt = ByteArray(SALT_BYTES_LENGTH)

                try {
                    if (IV_BYTES_LENGTH != input.read(iv) ||
                            SALT_BYTES_LENGTH != input.read(salt)) {
                        erl.onFailure(MSG_INVALID_INPUT_DATA, BadPaddingException())
                        exitProcess(1)
                    }
                } catch (e: IOException) {
                    erl.onFailure(MSG_CANNOT_READ, e)
                    exitProcess(1)
                }

                val key = getKey(password, salt)
                val ivParams = IvParameterSpec(iv)

                cipher.init(Cipher.DECRYPT_MODE, key, ivParams)

                try {
                    cis = CipherInputStream(input, cipher)

                    val buffer = ByteArray(8192)
                    var bytesCopied: Long = 0

                    var read = cis.read(buffer)
                    while (read > -1) {
                        fos.write(buffer, 0, read)
                        bytesCopied += read
                        erl.onProgress(read, bytesCopied)
                        read = cis.read(buffer)
                    }

                    erl.onSuccess(outputFile as T)

                } catch (e: IOException) {
                    outputFile.delete()
                    erl.onFailure(MSG_CANNOT_WRITE, e)
                } finally {
                    fos.flush()
                    fos.close()
                    cis?.close()
                }
            }

            else -> erl.onFailure(MSG_INPUT_TYPE_NOT_SUPPORTED, InvalidParameterException())

        }
    }
}
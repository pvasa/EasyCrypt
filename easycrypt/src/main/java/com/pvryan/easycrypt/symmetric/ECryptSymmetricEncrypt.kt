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
import com.pvryan.easycrypt.extensions.toBase64
import com.pvryan.easycrypt.extensions.toBase64String
import java.io.File
import java.io.IOException
import java.io.InputStream
import javax.crypto.Cipher
import javax.crypto.CipherOutputStream
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.system.exitProcess

internal class ECryptSymmetricEncrypt<out T>
(input: T,
 password: String,
 cipher: Cipher,
 getKey: (password: String, salt: ByteArray) -> SecretKeySpec,
 erl: ECryptResultListener,
 outputFile: File) : Constants() {

    init {

        val salt = ByteArray(SALT_BYTES_LENGTH)
        random.nextBytes(salt)

        val keySpec = getKey(password, salt)

        val iv = ByteArray(cipher.blockSize)
        random.nextBytes(iv)
        val ivParams = IvParameterSpec(iv)

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParams)

        when (input) {

            is ByteArray -> {

                try {
                    val output = iv.plus(salt).plus(cipher.doFinal(input))

                    if (outputFile.absolutePath != DEF_ENCRYPTED_FILE_PATH) {

                        if (outputFile.exists()) {
                            erl.onFailure(MSG_OUTPUT_FILE_EXISTS,
                                    FileAlreadyExistsException(outputFile))
                            exitProcess(1)
                        }

                        outputFile.outputStream().use {
                            it.write(output.toBase64())
                            it.flush()
                            @Suppress("UNCHECKED_CAST")
                            erl.onSuccess(outputFile as T)
                        }
                    } else {
                        erl.onSuccess(output.toBase64String())
                    }
                } catch (e: IOException) {
                    erl.onFailure(MSG_CANNOT_WRITE, e)
                }
            }

            is InputStream -> {

                val fos = outputFile.outputStream()
                var cos = CipherOutputStream(fos, cipher)

                try {
                    fos.write(iv)
                    fos.write(salt)
                    cos = CipherOutputStream(fos, cipher)

                    val buffer = ByteArray(8192)
                    var bytesCopied: Long = 0
                    var read = input.read(buffer)

                    while (read > -1) {
                        cos.write(buffer, 0, read)
                        bytesCopied += read
                        erl.onProgress(read, bytesCopied)
                        read = input.read(buffer)
                    }

                    @Suppress("UNCHECKED_CAST")
                    erl.onSuccess(outputFile as T)

                } catch (e: IOException) {
                    outputFile.delete()
                    erl.onFailure(MSG_CANNOT_WRITE, e)
                } finally {
                    cos.flush()
                    cos.close()
                    input.close()
                }
            }
        }
    }
}
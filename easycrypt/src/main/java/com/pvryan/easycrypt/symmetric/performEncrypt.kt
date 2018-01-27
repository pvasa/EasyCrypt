/**
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

package com.pvryan.easycrypt.symmetric

import com.pvryan.easycrypt.Constants
import com.pvryan.easycrypt.ECResultListener
import com.pvryan.easycrypt.extensions.handleSuccess
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStream
import java.security.InvalidParameterException
import javax.crypto.Cipher
import javax.crypto.CipherOutputStream
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal object performEncrypt {

    @JvmSynthetic
    internal fun <T> invoke(input: T,
                            password: String,
                            cipher: Cipher,
                            getKey: (password: String, salt: ByteArray) -> SecretKeySpec,
                            erl: ECResultListener,
                            outputFile: File) {

        if (outputFile.exists() && outputFile.absolutePath != Constants.DEF_ENCRYPTED_FILE_PATH) {
            when (input) { is InputStream -> input.close()
            }
            erl.onFailure(Constants.ERR_OUTPUT_FILE_EXISTS, FileAlreadyExistsException(outputFile))
            return
        }

        val salt = ByteArray(Constants.SALT_BYTES_LENGTH)
        Constants.random.nextBytes(salt)

        val keySpec = getKey(password, salt)

        val iv = ByteArray(cipher.blockSize)
        Constants.random.nextBytes(iv)
        val ivParams = IvParameterSpec(iv)

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParams)

        when (input) {

            is ByteArray -> (iv.plus(salt).plus(cipher.doFinal(input)))
                    .handleSuccess(erl, outputFile, true)

            is FileInputStream -> {

                if (outputFile.exists()) {
                    outputFile.delete()
                }
                outputFile.createNewFile()

                val fos = outputFile.outputStream()

                try {
                    fos.write(iv)
                    fos.write(salt)
                } catch (e: IOException) {
                    fos.flush()
                    fos.close()
                    input.close()
                    outputFile.delete()
                    erl.onFailure(Constants.ERR_CANNOT_WRITE, e)
                    return
                }

                val cos = CipherOutputStream(fos, cipher)

                try {
                    val size = input.channel.size()
                    val buffer = ByteArray(8192)
                    var bytesCopied: Long = 0
                    var read = input.read(buffer)

                    while (read > -1) {
                        cos.write(buffer, 0, read)
                        bytesCopied += read
                        erl.onProgress(read, bytesCopied, size)
                        read = input.read(buffer)
                    }

                } catch (e: IOException) {
                    outputFile.delete()
                    erl.onFailure(Constants.ERR_CANNOT_WRITE, e)
                    return
                } finally {
                    cos.flush()
                    cos.close()
                    input.close()
                }
                erl.onSuccess(outputFile)
            }

            else -> erl.onFailure(Constants.ERR_INPUT_TYPE_NOT_SUPPORTED, InvalidParameterException())

        }
    }
}

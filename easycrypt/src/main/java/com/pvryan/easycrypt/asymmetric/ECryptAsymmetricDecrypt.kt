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

package com.pvryan.easycrypt.asymmetric

import com.pvryan.easycrypt.Constants
import com.pvryan.easycrypt.ECryptResultListener
import com.pvryan.easycrypt.extensions.asByteArray
import com.pvryan.easycrypt.extensions.handleSuccess
import com.pvryan.easycrypt.extensions.size
import com.pvryan.easycrypt.symmetric.ECryptSymmetric
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.security.InvalidParameterException
import java.security.interfaces.RSAPrivateKey
import javax.crypto.Cipher

internal object performDecrypt {

    @JvmSynthetic
    internal fun <T> invoke(input: T,
                            privateKey: RSAPrivateKey,
                            cipher: Cipher,
                            erl: ECryptResultListener,
                            outputFile: File = File(Constants.DEF_DECRYPTED_FILE_PATH)) {

        if (outputFile.exists() && outputFile.absolutePath != Constants.DEF_DECRYPTED_FILE_PATH) {
            when (input) { is InputStream -> input.close()
            }
            erl.onFailure(Constants.MSG_OUTPUT_FILE_EXISTS, FileAlreadyExistsException(outputFile))
            return
        }

        val RSA_OUTPUT_SIZE = privateKey.size() / 8

        when (input) {

            is ByteArray -> {

                if (input.size > RSA_OUTPUT_SIZE) {

                    val passBytes = ByteArray(RSA_OUTPUT_SIZE)
                    val inputStream = input.inputStream()

                    inputStream.read(passBytes)

                    invoke(passBytes, privateKey, cipher, object : ECryptResultListener {

                        @Suppress("PARAMETER_NAME_CHANGED_ON_OVERRIDE")
                        override fun <T> onSuccess(password: T) {

                            ECryptSymmetric().decrypt(inputStream, password as String,
                                    object : ECryptResultListener {

                                        override fun <T> onSuccess(result: T) {
                                            (result as String).asByteArray()
                                                    .handleSuccess(erl, outputFile, false)
                                        }

                                        override fun onFailure(message: String, e: Exception) {
                                            erl.onFailure(message, e)
                                        }
                                    })
                        }

                        override fun onFailure(message: String, e: Exception) {
                            inputStream.close()
                            erl.onFailure(message, e)
                        }

                    }, outputFile)

                } else {
                    cipher.doFinal(input).handleSuccess(erl, outputFile, false)
                }
            }

            is FileInputStream -> {

                if (outputFile.exists()) {
                    outputFile.delete()
                }
                outputFile.createNewFile()

                val passCipher = ByteArray(RSA_OUTPUT_SIZE)
                input.read(passCipher)

                invoke(passCipher, privateKey, cipher, object : ECryptResultListener {

                    @Suppress("PARAMETER_NAME_CHANGED_ON_OVERRIDE")
                    override fun <T> onSuccess(password: T) {

                        ECryptSymmetric().decrypt(input, password as String,
                                object : ECryptResultListener {

                                    override fun <T> onSuccess(result: T) {
                                        erl.onSuccess(result)
                                    }

                                    override fun onFailure(message: String, e: Exception) {
                                        erl.onFailure(message, e)
                                    }

                                }, outputFile)
                    }

                    override fun onFailure(message: String, e: Exception) {
                        input.close()
                        erl.onFailure(message, e)
                    }
                })
            }

            else -> erl.onFailure(Constants.MSG_INPUT_TYPE_NOT_SUPPORTED, InvalidParameterException())

        }
    }
}

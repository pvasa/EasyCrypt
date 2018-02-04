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
package com.pvryan.easycrypt.asymmetric

import com.pvryan.easycrypt.Constants
import com.pvryan.easycrypt.ECKeys
import com.pvryan.easycrypt.ECResultListener
import com.pvryan.easycrypt.extensions.allowedInputSize
import com.pvryan.easycrypt.extensions.asByteArray
import com.pvryan.easycrypt.extensions.fromBase64
import com.pvryan.easycrypt.extensions.handleSuccess
import com.pvryan.easycrypt.symmetric.ECSymmetric
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStream
import java.security.interfaces.RSAPublicKey
import javax.crypto.Cipher

@Suppress("ClassName")
internal object performEncrypt {

    @JvmSynthetic
    internal fun <T> invoke(input: T,
                            publicKey: RSAPublicKey,
                            cipher: Cipher,
                            erl: ECResultListener,
                            outputFile: File = File(Constants.DEF_ENCRYPTED_FILE_PATH)) {

        if (outputFile.exists() && outputFile.absolutePath != Constants.DEF_ENCRYPTED_FILE_PATH) {
            when (input) { is InputStream -> input.close()
            }
            erl.onFailure(Constants.ERR_OUTPUT_FILE_EXISTS, FileAlreadyExistsException(outputFile))
            return
        }

        when (input) {

            is ByteArray -> {

                if (input.size > publicKey.allowedInputSize()) {

                    val password = ECKeys()
                            .genSecureRandomPassword(Constants.PASSWORD_LENGTH)

                    ECSymmetric().encrypt(input, password, object : ECResultListener {

                        override fun <T> onSuccess(result: T) {

                            invoke(password.asByteArray(), publicKey,
                                    cipher, object : ECResultListener {

                                @Suppress("PARAMETER_NAME_CHANGED_ON_OVERRIDE")
                                override fun <T> onSuccess(cipherPass: T) {
                                    try {
                                        ((cipherPass as String).fromBase64()
                                                .plus((result as String).fromBase64()))
                                                .handleSuccess(erl, outputFile, true)
                                    } catch (e: IllegalArgumentException) {
                                        erl.onFailure(Constants.ERR_BAD_BASE64, e)
                                    }
                                }

                                override fun onFailure(message: String, e: Exception) {
                                    erl.onFailure(message, e)
                                }
                            }, outputFile)
                        }

                        override fun onFailure(message: String, e: Exception) {
                            erl.onFailure(message, e)
                        }
                    })

                } else {
                    cipher.doFinal(input).handleSuccess(erl, outputFile, true)
                }
            }

            is FileInputStream -> {

                if (outputFile.exists()) {
                    outputFile.delete()
                }
                outputFile.createNewFile()

                val password = ECKeys()
                        .genSecureRandomPassword(Constants.PASSWORD_LENGTH)

                File(Constants.DEF_EXT_TEMP_DIR_PATH).mkdirs()
                val tempFile = File(Constants.DEF_EXT_TEMP_DIR_PATH, Constants.ENCRYPTED_FILE_NAME + Constants.ECRYPT_FILE_EXT)
                if (tempFile.exists()) tempFile.delete()

                ECSymmetric().encrypt(input, password, object : ECResultListener {

                    override fun onProgress(newBytes: Int, bytesProcessed: Long, totalBytes: Long) {
                        erl.onProgress(newBytes, bytesProcessed, input.channel.size())
                    }

                    override fun <T> onSuccess(result: T) {

                        invoke(password.asByteArray(),
                                publicKey, cipher, object : ECResultListener {

                            @Suppress("PARAMETER_NAME_CHANGED_ON_OVERRIDE")
                            override fun <T> onSuccess(passCipher: T) {

                                val fos = outputFile.outputStream()

                                val asOutputFile = result as File

                                asOutputFile.inputStream().use {

                                    try {
                                        val passBytes = (passCipher as String).fromBase64()
                                        fos.write(passBytes, 0, passBytes.size)
                                        val buffer = ByteArray(8192)
                                        var read = it.read(buffer)
                                        while (read > -1) {
                                            fos.write(buffer, 0, read)
                                            read = it.read(buffer)
                                        }
                                    } catch (e: IllegalArgumentException) {
                                        erl.onFailure(Constants.ERR_BAD_BASE64, e)
                                        return
                                    } catch (e: IOException) {
                                        erl.onFailure(Constants.ERR_CANNOT_WRITE, e)
                                        return
                                    } finally {
                                        fos.flush()
                                        fos.close()
                                        asOutputFile.delete()
                                    }
                                    erl.onSuccess(outputFile)
                                }
                            }

                            override fun onFailure(message: String, e: Exception) {
                                erl.onFailure(message, e)
                            }
                        })
                    }

                    override fun onFailure(message: String, e: Exception) {
                        erl.onFailure(message, e)
                    }
                }, tempFile)
            }
        }
    }
}

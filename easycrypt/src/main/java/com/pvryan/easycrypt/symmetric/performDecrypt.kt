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

package com.pvryan.easycrypt.symmetric

import com.pvryan.easycrypt.Constants
import com.pvryan.easycrypt.ECResultListener
import com.pvryan.easycrypt.extensions.handleSuccess
import java.io.*
import java.security.InvalidParameterException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.IllegalBlockSizeException
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

@Suppress("ClassName", "LocalVariableName")
internal object performDecrypt {

    @JvmSynthetic
    internal fun <T> invoke(input: T,
                            password: String,
                            cipher: Cipher,
                            getKey: (password: String, salt: ByteArray) -> SecretKeySpec,
                            erl: ECResultListener,
                            outputFile: File) {

        if (outputFile.exists() && outputFile.absolutePath != Constants.DEF_DECRYPTED_FILE_PATH) {
            when (input) { is InputStream -> input.close()
            }
            erl.onFailure(Constants.ERR_OUTPUT_FILE_EXISTS, FileAlreadyExistsException(outputFile))
            return
        }

        val IV_BYTES_LENGTH = cipher.blockSize

        when (input) {

            is ByteArrayInputStream -> {

                val IV = ByteArray(IV_BYTES_LENGTH)
                val salt = ByteArray(Constants.SALT_BYTES_LENGTH)

                if (IV_BYTES_LENGTH != input.read(IV) || Constants.SALT_BYTES_LENGTH != input.read(salt)) {
                    input.close()
                    erl.onFailure(Constants.ERR_INVALID_INPUT_DATA, BadPaddingException())
                    return
                }

                val ivParams = IvParameterSpec(IV)
                val key = getKey(password, salt)

                try {
                    cipher.init(Cipher.DECRYPT_MODE, key, ivParams)

                    val secureBytes = input.readBytes()
                    cipher.doFinal(secureBytes).handleSuccess(erl, outputFile, false)

                } catch (e: BadPaddingException) {
                    erl.onFailure(Constants.ERR_INVALID_INPUT_DATA, e)
                } catch (e: IllegalBlockSizeException) {
                    erl.onFailure(Constants.ERR_INVALID_INPUT_DATA, e)
                } finally {
                    input.close()
                }
            }

            is FileInputStream -> {

                if (outputFile.exists()) {
                    outputFile.delete()
                }
                outputFile.createNewFile()

                var cis: CipherInputStream? = null
                val fos = outputFile.outputStream()

                val iv = ByteArray(IV_BYTES_LENGTH)
                val salt = ByteArray(Constants.SALT_BYTES_LENGTH)

                try {
                    if (IV_BYTES_LENGTH != input.read(iv) ||
                            Constants.SALT_BYTES_LENGTH != input.read(salt)) {
                        input.close()
                        erl.onFailure(Constants.ERR_INVALID_INPUT_DATA, BadPaddingException())
                        return
                    }
                } catch (e: IOException) {
                    input.close()
                    erl.onFailure(Constants.ERR_CANNOT_READ, e)
                    return
                }

                val key = getKey(password, salt)
                val ivParams = IvParameterSpec(iv)

                cipher.init(Cipher.DECRYPT_MODE, key, ivParams)

                try {
                    val size = input.channel.size()
                    cis = CipherInputStream(input, cipher)

                    val buffer = ByteArray(8192)
                    var bytesCopied: Long = 0

                    var read = cis.read(buffer)
                    while (read > -1) {
                        fos.write(buffer, 0, read)
                        bytesCopied += read
                        erl.onProgress(read, bytesCopied, size)
                        read = cis.read(buffer)
                    }

                } catch (e: IOException) {
                    outputFile.delete()
                    erl.onFailure(Constants.ERR_CANNOT_WRITE, e)
                    return
                } finally {
                    fos.flush()
                    fos.close()
                    cis?.close()
                }
                erl.onSuccess(outputFile)
            }

            else -> erl.onFailure(Constants.ERR_INPUT_TYPE_NOT_SUPPORTED, InvalidParameterException())

        }
    }
}

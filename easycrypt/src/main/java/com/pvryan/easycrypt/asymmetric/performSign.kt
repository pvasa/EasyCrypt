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
import com.pvryan.easycrypt.ECResultListener
import com.pvryan.easycrypt.extensions.handleSuccess
import org.jetbrains.anko.AnkoLogger
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStream
import java.security.InvalidParameterException
import java.security.Signature
import java.security.SignatureException
import java.security.interfaces.RSAPrivateKey

@Suppress("ClassName")
internal object performSign : AnkoLogger {

    private val signature = Signature.getInstance(Constants.SIGNATURE_ALGORITHM)

    @JvmSynthetic
    internal fun <T> invoke(input: T,
                            privateKey: RSAPrivateKey,
                            erl: ECResultListener,
                            outputFile: File) {

        if (outputFile.exists()) {
            if (input is InputStream) input.close()
            erl.onFailure(Constants.ERR_OUTPUT_FILE_EXISTS, FileAlreadyExistsException(outputFile))
            return
        }

        signature.initSign(privateKey)

        when (input) {

            is InputStream -> {

                val buffer = ByteArray(8192)
                var bytesCopied: Long = 0

                try {
                    val size = if (input is FileInputStream) input.channel.size() else -1
                    var read = input.read(buffer)

                    while (read > -1) {
                        signature.update(buffer, 0, read)
                        bytesCopied += read
                        erl.onProgress(read, bytesCopied, size)
                        read = input.read(buffer)
                    }

                    signature.sign().handleSuccess(erl, outputFile, true)

                } catch (e: IOException) {
                    outputFile.delete()
                    erl.onFailure(Constants.ERR_CANNOT_WRITE, e)
                } catch (e: SignatureException) {
                    outputFile.delete()
                    erl.onFailure(Constants.ERR_SIGN_EXCEPTION, e)
                }
            }

            else -> erl.onFailure(Constants.ERR_INPUT_TYPE_NOT_SUPPORTED, InvalidParameterException())
        }
    }
}

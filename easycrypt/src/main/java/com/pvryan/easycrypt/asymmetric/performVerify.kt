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
import com.pvryan.easycrypt.extensions.asString
import com.pvryan.easycrypt.extensions.fromBase64
import org.jetbrains.anko.AnkoLogger
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.security.InvalidParameterException
import java.security.Signature
import java.security.SignatureException
import java.security.interfaces.RSAPublicKey

internal object performVerify : AnkoLogger {

    private val signature = Signature.getInstance(Constants.SIGNATURE_ALGORITHM)

    @JvmSynthetic
    internal fun <T> invoke(input: T,
                            publicKey: RSAPublicKey,
                            sigFile: File,
                            evl: ECVerifiedListener) {

        signature.initVerify(publicKey)

        when (input) {

            is InputStream -> {

                val buffer = ByteArray(8192)
                var bytesCopied: Long = 0

                try {
                    var read = input.read(buffer)

                    while (read > -1) {
                        signature.update(buffer, 0, read)
                        bytesCopied += read
                        evl.onProgress(read, bytesCopied)
                        read = input.read(buffer)
                    }

                    try {
                        evl.onSuccess(signature.verify(
                                sigFile.readBytes().asString().fromBase64()))
                    } catch (e: SignatureException) {
                        evl.onFailure(Constants.ERR_VERIFY_EXCEPTION, e)
                    }

                } catch (e: IOException) {
                    evl.onFailure(Constants.ERR_CANNOT_WRITE, e)
                }

            }

            else -> evl.onFailure(Constants.ERR_INPUT_TYPE_NOT_SUPPORTED, InvalidParameterException())

        }
    }
}

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

import android.os.Build
import com.pvryan.easycrypt.Constants
import com.pvryan.easycrypt.ECResultListener
import com.pvryan.easycrypt.PRNGFixes
import com.pvryan.easycrypt.extensions.asByteArray
import com.pvryan.easycrypt.extensions.fromBase64
import org.jetbrains.annotations.NotNull
import timber.log.Timber
import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.security.InvalidKeyException
import java.security.InvalidParameterException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException

/**
 * Secure symmetric encryption with AES256.
 */
class ECSymmetric(transformation: ECSymmetricTransformations = ECSymmetricTransformations.AesCbcPkcs7Padding) {

    @PublishedApi
    internal val cipher = Cipher.getInstance(transformation.value)

    init {
        when {
            Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT -> PRNGFixes.apply()
        }
    }

    /**
     * Symmetrically encrypts the input data using AES algorithm in CBC mode with PKCS7Padding padding
     * and posts response to [ECResultListener.onSuccess] if successful or
     * posts error to [ECResultListener.onFailure] if failed.
     * Encryption progress is posted to [ECResultListener.onProgress].
     * Result can be a String or a File depending on the data type of [input] and parameter [outputFile].
     *
     * @param T datatype of expected result
     * @param input data to be encrypted. It can be of type
     * [String], [CharSequence], [ByteArray], [InputStream], [java.io.FileInputStream], or [File]
     * @param password string used to encrypt input
     * @param outputFile optional output file. If provided, result will be written to this file
     *
     * @exception InvalidKeyException if password is null or blank
     * @exception NoSuchFileException if input is a File which does not exists or is a Directory
     * @exception InvalidParameterException if input data type is not supported
     * @exception IOException if cannot read or write to a file
     * @exception FileAlreadyExistsException if output file is provided and already exists
     * @exception IllegalBlockSizeException if this cipher is a block cipher,
     * no padding has been requested (only in encryption mode), and the total
     * input length of the data processed by this cipher is not a multiple of
     * block size; or if this encryption algorithm is unable to
     * process the input data provided.
     */
    @JvmOverloads
    inline fun <reified T> encrypt(
            @NotNull input: Any,
            @NotNull password: String,
            @NotNull outputFile: File = File(Constants.DEF_ENCRYPTED_FILE_PATH)
    ): ECResultListener<T> {

        val erl = ECResultListener<T>()

        val tPass = password.trim()

        val parsedInput: Any = when (input) {
            is String -> input.asByteArray()
            is CharSequence -> input.toString().asByteArray()
            is ByteArrayInputStream -> input.readBytes()
            is File -> {
                if (!input.exists() || input.isDirectory) {
                    erl.onFailure?.invoke(Constants.ERR_NO_SUCH_FILE, NoSuchFileException(input))
                    return erl
                }
                input.inputStream()
            }
            is InputStream -> input
            else -> {
                erl.onFailure?.invoke(Constants.ERR_INPUT_TYPE_NOT_SUPPORTED, InvalidParameterException())
                return erl
            }
        }

        val parsedOutputFile =
                if (input !is File || outputFile.absolutePath != Constants.DEF_ENCRYPTED_FILE_PATH) outputFile
                else File(input.absolutePath + Constants.ECRYPT_FILE_EXT)

        if (parsedOutputFile.exists() && parsedOutputFile.absolutePath != Constants.DEF_ENCRYPTED_FILE_PATH) {
            (input as? InputStream)?.close()
            erl.onFailure?.invoke(Constants.ERR_OUTPUT_FILE_EXISTS, FileAlreadyExistsException(parsedOutputFile))
            return erl
        }

        encryptSymmetric(parsedInput, tPass, cipher, erl, parsedOutputFile)
        return erl
    }

    /**
     * Symmetrically decrypts the input data using AES algorithm in CBC mode with PKCS7Padding padding
     * and posts response to [ECResultListener.onSuccess] if successful or
     * posts error to [ECResultListener.onFailure] if failed.
     * Decryption progress is posted to [ECResultListener.onProgress].
     * Result can be a String or a File depending on the data type of [input] and parameter [outputFile]
     *
     * @param input input data to be decrypted. It can be of type
     * [String], [CharSequence], [ByteArray], [InputStream], [java.io.FileInputStream], or [File]
     * @param password password string used to PerformEncrypt input
     * @param outputFile optional output file. If provided, result will be written to this file
     *
     * @exception InvalidKeyException if password is null or blank
     * @exception NoSuchFileException if input is a File which does not exists or is a Directory
     * @exception InvalidParameterException if input data type is not supported
     * @exception IOException if cannot read or write to a file
     * @exception FileAlreadyExistsException if output file is provided and already exists
     * @exception IllegalArgumentException if input data is not in valid format
     * @exception IllegalBlockSizeException if this cipher is a block cipher,
     * no padding has been requested (only in encryption mode), and the total
     * input length of the data processed by this cipher is not a multiple of
     * block size; or if this encryption algorithm is unable to
     * process the input data provided.
     * @exception BadPaddingException if this cipher is in decryption mode,
     * and (un)padding has been requested, but the decrypted data is not
     * bounded by the appropriate padding bytes
     */
    @JvmOverloads
    inline fun <reified T> decrypt(
            @NotNull input: Any,
            @NotNull password: String,
            @NotNull outputFile: File = File(Constants.DEF_DECRYPTED_FILE_PATH)
    ): ECResultListener<T> {

        val erl = ECResultListener<T>()

        val tPass = password.trim()

        val parsedInput: Any = when (input) {
            is String -> try {
                input.fromBase64().inputStream()
            } catch (e: IllegalArgumentException) {
                Timber.d(e)
                erl.onFailure?.invoke(Constants.ERR_BAD_BASE64, e)
                return erl
            }
            is CharSequence -> try {
                input.toString().fromBase64().inputStream()
            } catch (e: IllegalArgumentException) {
                Timber.d(e)
                erl.onFailure?.invoke(Constants.ERR_BAD_BASE64, e)
                return erl
            }
            is ByteArray -> input.inputStream()
            is File -> {
                if (!input.exists() || input.isDirectory) {
                    erl.onFailure?.invoke(Constants.ERR_NO_SUCH_FILE, NoSuchFileException(input))
                    return erl
                }
                input.inputStream()
            }
            is InputStream -> input
            else -> {
                erl.onFailure?.invoke(Constants.ERR_INPUT_TYPE_NOT_SUPPORTED, InvalidParameterException())
                return erl
            }
        }

        val parsedOutputFile =
                if (input !is File || outputFile.absolutePath != Constants.DEF_DECRYPTED_FILE_PATH) outputFile
                else File(input.absoluteFile.toString().removeSuffix(Constants.ECRYPT_FILE_EXT))

        if (parsedOutputFile.exists() && parsedOutputFile.absolutePath != Constants.DEF_DECRYPTED_FILE_PATH) {
            (input as? InputStream)?.close()
            erl.onFailure?.invoke(Constants.ERR_OUTPUT_FILE_EXISTS, FileAlreadyExistsException(parsedOutputFile))
            return erl
        }

        decryptSymmetric(parsedInput, tPass, cipher, erl, parsedOutputFile)
        return erl
    }
}

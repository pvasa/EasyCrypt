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
package com.pvryan.easycrypt.asymmetric

import com.pvryan.easycrypt.Constants
import com.pvryan.easycrypt.ECKeys
import com.pvryan.easycrypt.ECResultListener
import com.pvryan.easycrypt.extensions.allowedInputSize
import com.pvryan.easycrypt.extensions.asByteArray
import com.pvryan.easycrypt.extensions.fromBase64
import com.pvryan.easycrypt.extensions.handleSuccess
import com.pvryan.easycrypt.extensions.size
import com.pvryan.easycrypt.symmetric.ECSymmetric
import kotlinx.coroutines.experimental.CoroutineScope
import kotlinx.coroutines.experimental.Dispatchers
import kotlinx.coroutines.experimental.Job
import kotlinx.coroutines.experimental.android.Main
import kotlinx.coroutines.experimental.launch
import org.jetbrains.annotations.NotNull
import timber.log.Timber
import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.security.InvalidKeyException
import java.security.InvalidParameterException
import java.security.Key
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import kotlin.coroutines.experimental.CoroutineContext

/**
 * Secure asymmetric encryption with RSA.
 */
class ECAsymmetric : CoroutineScope {

    private val job = Job()

    @PublishedApi
    internal val cipher: Cipher = Cipher.getInstance(Constants.ASYMMETRIC_TRANSFORMATION)

    override val coroutineContext: CoroutineContext = job + Dispatchers.Main

    /**
     * Encrypts the input data using RSA algorithm with OAEPwithSHA-256andMGF1Padding padding
     * and posts response to [ECResultListener.onSuccess] if successful or
     * posts error to [ECResultListener.onFailure] if failed.
     * Encryption progress is posted to [ECResultListener.onProgress].
     * Result can be a String or a File depending on the data type of [input] and parameter [outputFile].
     *
     * @param T datatype of expected result
     * @param input data to be encrypted. It can be of type
     * [String], [CharSequence], [ByteArrayInputStream], [ByteArray], [InputStream], [java.io.FileInputStream],or [File]
     * @param publicKey to encrypt the input, in X.509 format
     * @param outputFile optional output file. If provided, result will be written to this file
     *
     * @exception NoSuchFileException if input is a File which does not exists or is a Directory
     * @exception InvalidParameterException if input data type is not supported
     * @exception IOException if cannot read or write to a file
     * @exception FileAlreadyExistsException if output file is provided and already exists
     */
    @JvmOverloads
    inline fun <reified T> encrypt(
            @NotNull input: Any,
            @NotNull publicKey: RSAPublicKey,
            @NotNull outputFile: File = File(Constants.DEF_ENCRYPTED_FILE_PATH)
    ): ECResultListener<T> {

        val erl = ECResultListener<T>()

        launch {

            try {
                cipher.init(Cipher.ENCRYPT_MODE, publicKey as Key)
            } catch (e: InvalidKeyException) {
                Timber.d(e)
                erl.onFailure?.invoke(Constants.ERR_INVALID_KEY, e)
                return@launch
            }

            val parsedInput: Any = when (input) {

                is ByteArrayInputStream -> input.readBytes()
                is ByteArray -> input
                is String -> input.asByteArray()
                is CharSequence -> input.toString().asByteArray()
                is File -> {
                    if (!input.exists() || input.isDirectory) {
                        erl.onFailure?.invoke(Constants.ERR_NO_SUCH_FILE, NoSuchFileException(input))
                        return@launch
                    }
                    input.inputStream()
                }
                is InputStream -> input
                else -> {
                    Timber.d(Constants.ERR_INPUT_TYPE_NOT_SUPPORTED)
                    erl.onFailure?.invoke(Constants.ERR_INPUT_TYPE_NOT_SUPPORTED, IllegalArgumentException())
                    return@launch
                }
            }

            val parsedOutputFile = if (input is File) {
                if (outputFile.absolutePath != Constants.DEF_ENCRYPTED_FILE_PATH) outputFile
                else File(input.absolutePath + Constants.ECRYPT_FILE_EXT)
            } else outputFile

            if (parsedOutputFile.exists() && parsedOutputFile.absolutePath != Constants.DEF_ENCRYPTED_FILE_PATH) {
                (parsedInput as? InputStream)?.close()
                Timber.d(Constants.ERR_OUTPUT_FILE_EXISTS)
                erl.onFailure?.invoke(Constants.ERR_OUTPUT_FILE_EXISTS, FileAlreadyExistsException(parsedOutputFile))
                return@launch
            }

            when (parsedInput) {
                is ByteArray -> {
                    if (parsedInput.size <= publicKey.allowedInputSize()) {
                        cipher.doFinal(parsedInput).handleSuccess(erl, parsedOutputFile, true)
                        return@launch
                    }

                    val password = ECKeys().genSecureRandomPassword(Constants.PASSWORD_LENGTH)

                    ECSymmetric()
                            .encrypt<String>(input, password, parsedOutputFile)
                            .onSuccess { result ->
                                val erlTemp = ECResultListener<String>().apply {
                                    onSuccess { cipherPass ->
                                        try {
                                            (cipherPass.fromBase64().plus(result.fromBase64()))
                                                    .handleSuccess(erl, parsedOutputFile, true)
                                        } catch (e: IllegalArgumentException) {
                                            Timber.d(e)
                                            erl.onFailure?.invoke(Constants.ERR_BAD_BASE64, e)
                                        }
                                    }
                                    onFailure { message, e ->
                                        Timber.d(e)
                                        erl.onFailure?.invoke(message, e)
                                    }
                                }
                                cipher.doFinal(password.asByteArray()).handleSuccess(erlTemp, File(Constants.DEF_ENCRYPTED_FILE_PATH), true)
                            }
                            .onFailure { message, e ->
                                Timber.d(e)
                                erl.onFailure?.invoke(message, e)
                            }
                }
                is InputStream -> {

                    with(parsedOutputFile) {
                        if (exists()) delete()
                        createNewFile()
                    }

                    val password = ECKeys().genSecureRandomPassword(Constants.PASSWORD_LENGTH)

                    File(Constants.DEF_EXT_TEMP_DIR_PATH).mkdirs()
                    val tempFile = File(
                            Constants.DEF_EXT_TEMP_DIR_PATH,
                            Constants.ENCRYPTED_FILE_NAME + Constants.ECRYPT_FILE_EXT
                    ).apply { if (exists()) delete() }

                    ECSymmetric()
                            .encrypt<File>(parsedInput, password, tempFile)
                            .onProgress { newBytes, bytesProcessed, totalBytes ->
                                erl.onProgress?.invoke(newBytes, bytesProcessed, totalBytes)
                            }
                            .onSuccess { asOutputFile ->

                                val erlTemp = ECResultListener<String>().apply {
                                    onSuccess { cipherPass ->

                                        val fos = parsedOutputFile.outputStream()

                                        asOutputFile.inputStream().use {

                                            try {
                                                val passBytes = cipherPass.fromBase64()
                                                fos.write(passBytes, 0, passBytes.size)
                                                val buffer = ByteArray(8192)
                                                var read = it.read(buffer)
                                                while (read > -1) {
                                                    fos.write(buffer, 0, read)
                                                    read = it.read(buffer)
                                                }
                                            } catch (e: IllegalArgumentException) {
                                                Timber.d(e)
                                                erl.onFailure?.invoke(Constants.ERR_BAD_BASE64, e)
                                                return@use
                                            } catch (e: IOException) {
                                                Timber.d(e)
                                                erl.onFailure?.invoke(Constants.ERR_CANNOT_WRITE, e)
                                                return@use
                                            } finally {
                                                fos.flush()
                                                fos.close()
                                                asOutputFile.delete()
                                            }
                                            erl.onSuccess?.invoke(parsedOutputFile as T)
                                        }
                                    }
                                    onFailure { message, e ->
                                        Timber.d(e)
                                        erl.onFailure?.invoke(message, e)
                                    }
                                }
                                cipher.doFinal(password.asByteArray()).handleSuccess(erlTemp, File(Constants.DEF_ENCRYPTED_FILE_PATH), true)
                            }
                            .onFailure { message, e ->
                                Timber.d(e)
                                erl.onFailure?.invoke(message, e)
                            }
                }
            }
        }
        return erl
    }

    /**
     * Decrypts the input data using RSA algorithm with OAEPwithSHA-256andMGF1Padding padding
     * and posts response to [ECResultListener.onSuccess] if successful or
     * posts error to [ECResultListener.onFailure] if failed.
     * Decryption progress is posted to [ECResultListener.onProgress].
     * Result can be a String or a File depending on the data type of [input] and parameter [outputFile]
     *
     * @param T datatype of expected result
     * @param input data to be decrypted. It can be of type
     * [String], [CharSequence], [ByteArrayInputStream], [ByteArray], [InputStream], [java.io.FileInputStream],or [File]
     * @param privateKey to decrypt the data, in PKCS#8 format
     * @param outputFile optional output file. If provided, result will be written to this file
     *
     * @exception NoSuchFileException if input is a File which does not exists or is a Directory
     * @exception InvalidParameterException if input data type is not supported
     * @exception IOException if cannot read or write to a file
     * @exception FileAlreadyExistsException if output file is provided and already exists
     * @exception IllegalArgumentException if input data is not in valid format
     */
    @JvmOverloads
    inline fun <reified T> decrypt(
            @NotNull input: Any,
            @NotNull privateKey: RSAPrivateKey,
            @NotNull outputFile: File = File(Constants.DEF_DECRYPTED_FILE_PATH)
    ): ECResultListener<T> {

        val erl = ECResultListener<T>()

        launch {

            try {
                cipher.init(Cipher.DECRYPT_MODE, privateKey)
            } catch (e: InvalidKeyException) {
                Timber.d(e)
                erl.onFailure?.invoke(Constants.ERR_INVALID_KEY, e)
                return@launch
            }

            val parsedInput: Any = when (input) {
                is ByteArrayInputStream -> input.readBytes()
                is String -> try {
                    input.fromBase64()
                } catch (e: IllegalArgumentException) {
                    Timber.d(e)
                    erl.onFailure?.invoke(Constants.ERR_BAD_BASE64, e)
                    return@launch
                }
                is CharSequence -> try {
                    input.toString().fromBase64()
                } catch (e: IllegalArgumentException) {
                    Timber.d(e)
                    erl.onFailure?.invoke(Constants.ERR_BAD_BASE64, e)
                    return@launch
                }
                is File -> input.inputStream()
                is InputStream -> input
                else -> {
                    erl.onFailure?.invoke(Constants.ERR_INPUT_TYPE_NOT_SUPPORTED, IllegalArgumentException())
                    return@launch
                }
            }

            val parsedOutputFile = if (input is File) {
                if (!input.exists() || input.isDirectory) {
                    erl.onFailure?.invoke(Constants.ERR_NO_SUCH_FILE, NoSuchFileException(input))
                    return@launch
                }
                if (outputFile.absolutePath != Constants.DEF_ENCRYPTED_FILE_PATH) outputFile
                else File(input.absolutePath + Constants.ECRYPT_FILE_EXT)
            } else outputFile

            if (parsedOutputFile.exists() && parsedOutputFile.absolutePath != Constants.DEF_DECRYPTED_FILE_PATH) {
                (parsedInput as? InputStream)?.close()
                erl.onFailure?.invoke(Constants.ERR_OUTPUT_FILE_EXISTS, FileAlreadyExistsException(parsedOutputFile))
                return@launch
            }

            val rsaOutputSize = privateKey.size() / 8

            when (parsedInput) {

                is ByteArray -> {

                    if (parsedInput.size > rsaOutputSize) {

                        val passBytes = ByteArray(rsaOutputSize)
                        val inputStream = parsedInput.inputStream()

                        inputStream.read(passBytes)

                        val erlTemp = ECResultListener<String>().apply {
                            onSuccess { password ->
                                ECSymmetric()
                                        .decrypt<String>(inputStream, password)
                                        .onSuccess { result ->
                                            result.asByteArray().handleSuccess(erl, parsedOutputFile, false)
                                        }
                                        .onFailure { message, e -> erl.onFailure?.invoke(message, e) }
                            }
                            onFailure { message, e ->
                                inputStream.close()
                                erl.onFailure?.invoke(message, e)
                            }
                        }
                        cipher.doFinal(passBytes).handleSuccess(erlTemp, File(Constants.DEF_DECRYPTED_FILE_PATH), false)
                    } else {
                        try {
                            cipher.doFinal(parsedInput).handleSuccess(erl, parsedOutputFile, false)
                        } catch (e: BadPaddingException) {
                            Timber.d(e)
                            erl.onFailure?.invoke(Constants.ERR_INVALID_INPUT_DATA, e)
                        } catch (e: IllegalBlockSizeException) {
                            Timber.d(e)
                            erl.onFailure?.invoke(Constants.ERR_INVALID_INPUT_DATA, e)
                        }
                    }
                }

                is InputStream -> {

                    with(parsedOutputFile) {
                        if (exists()) delete()
                        createNewFile()
                    }

                    val passCipher = ByteArray(rsaOutputSize)
                    parsedInput.read(passCipher)

                    val erlTemp = ECResultListener<String>().apply {
                        onSuccess { password ->
                            ECSymmetric()
                                    .decrypt<File>(parsedInput, password, parsedOutputFile)
                                    .onProgress { newBytes, bytesProcessed, totalBytes ->
                                        erl.onProgress?.invoke(newBytes, bytesProcessed, totalBytes)
                                    }
                                    .onSuccess { erl.onSuccess?.invoke(it as T) }
                                    .onFailure { message, e -> erl.onFailure?.invoke(message, e) }
                        }
                        onFailure { message, e ->
                            parsedInput.close()
                            erl.onFailure?.invoke(message, e)
                        }
                    }
                    cipher.doFinal(passCipher).handleSuccess(erlTemp, File(Constants.DEF_DECRYPTED_FILE_PATH), false)
                }
            }
        }
        return erl
    }

    /**
     * Signs the input data using provided RSA private key (SHA512withRSA algorithm)
     * and posts response to [ECResultListener.onSuccess] if successful or
     * posts error to [ECResultListener.onFailure] if failed.
     * Signing progress is posted to [ECResultListener.onProgress].
     * Result is a File with the generated signature
     *
     * @param input data to be signed. It can be of type
     * [String], [CharSequence], [ByteArray], [InputStream], [java.io.FileInputStream], or [File]
     * @param privateKey to be used for signing [input] data, in PKCS#8 format
     * @param outputFile output signature will be saved to this file
     *
     * @exception NoSuchFileException if input is a File which does not exists or is a Directory
     * @exception InvalidParameterException if input data type is not supported
     * @exception IOException if cannot read or write to a file
     * @exception FileAlreadyExistsException if output file is provided and already exists
     * @exception java.security.SignatureException if this signature algorithm is unable to process the input data provided
     */
    fun sign(input: Any, privateKey: RSAPrivateKey, outputFile: File): ECResultListener<File> {

        val erl = ECResultListener<File>()

        val parsedInput: Any = when (input) {

            is ByteArray -> input.inputStream()
            is String -> input.asByteArray().inputStream()
            is CharSequence -> input.toString().asByteArray().inputStream()
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
        asymmetricSign(parsedInput, privateKey, erl, outputFile)
        return erl
    }

    /**
     * Verifies the input data using provided RSA public key (SHA512withRSA algorithm)
     * and posts response to [ECResultListener.onSuccess] if successful or
     * posts error to [ECResultListener.onFailure] if error.
     * Verification progress is posted to [ECResultListener.onProgress].
     * Result is a boolean. True if data is successfully verified otherwise false
     *
     * @param input input data to be signed. It can be of type
     * [String], [CharSequence], [ByteArray], [InputStream], [java.io.FileInputStream], or [File]
     * @param publicKey to verify input data, in X.509 format
     * @param signature expected to match and verify input data
     *
     * @exception NoSuchFileException if input is a File which does not exists or is a Directory
     * @exception InvalidParameterException if input data type is not supported
     * @exception IOException if cannot read from or write to a file
     * @exception FileAlreadyExistsException if output file is provided and already exists
     * @exception IllegalArgumentException if input data is not in valid format
     * @exception java.security.SignatureException if cannot use provided signature to verify input data
     */
    fun verify(
            input: Any,
            publicKey: RSAPublicKey,
            signature: File
    ): ECResultListener<Boolean> {

        val erl = ECResultListener<Boolean>()

        val parsedInput: Any = when (input) {
            is ByteArray -> input.inputStream()
            is String -> input.asByteArray().inputStream()
            is CharSequence -> input.toString().asByteArray().inputStream()
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
        asymmetricVerify(parsedInput, publicKey, signature, erl)
        return erl
    }

    /**
     * Key sizes that can be used for generating RSA key pairs
     */
    sealed class KeySizes(val value: Int) {
        object S_2048 : KeySizes(2048)
        object S_4096 : KeySizes(4096) // Default
    }
}

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
import com.pvryan.easycrypt.extensions.asString
import com.pvryan.easycrypt.extensions.fromBase64
import com.pvryan.easycrypt.extensions.size
import com.pvryan.easycrypt.extensions.toBase64
import com.pvryan.easycrypt.extensions.toBase64String
import com.pvryan.easycrypt.parse
import com.pvryan.easycrypt.symmetric.ECSymmetric
import com.pvryan.easycrypt.symmetric.ProgressListener
import com.pvryan.easycrypt.symmetric.isDefault
import kotlinx.coroutines.experimental.GlobalScope
import kotlinx.coroutines.experimental.async
import org.jetbrains.annotations.NotNull
import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.security.InvalidParameterException
import java.security.Key
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import javax.crypto.Cipher

/**
 * Secure asymmetric encryption with RSA.
 */
class ECAsymmetric {

    @PublishedApi
    internal val cipher: Cipher = Cipher.getInstance(Constants.ASYMMETRIC_TRANSFORMATION)

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
            @NotNull outputFile: File = File(Constants.DEF_ENCRYPTED_FILE_PATH),
            noinline progressListener: ProgressListener?
    ) = GlobalScope.async {

        val (parsedInput, parsedOutputFile) = Triple(input, outputFile, true).parse()

        cipher.init(Cipher.ENCRYPT_MODE, publicKey as Key)

        when (parsedInput) {

            is ByteArray -> {

                if (parsedInput.size <= publicKey.allowedInputSize()) {

                    with(cipher.doFinal(parsedInput)) {
                        return@async if (!parsedOutputFile.isDefault()) {
                            parsedOutputFile.outputStream().use {
                                it.write(toBase64())
                                it.flush()
                            }
                            parsedOutputFile
                        } else toBase64String() as T
                    }
                }

                val password = ECKeys().genSecureRandomPassword(Constants.PASSWORD_LENGTH)

                val symmetricResult = ECSymmetric().encrypt<String>(parsedInput, password, parsedOutputFile)
                symmetricResult.await()
                symmetricResult.getCompletionExceptionOrNull()?.let { throw it }

                val cipherPass = cipher.doFinal(password.asByteArray()).toBase64String()
                val finalResult = (cipherPass.fromBase64().plus(symmetricResult.getCompleted().fromBase64()))

                return@async if (!parsedOutputFile.isDefault()) {
                    parsedOutputFile.outputStream().use {
                        it.write(finalResult.toBase64())
                        it.flush()
                    }
                    parsedOutputFile
                } else finalResult.toBase64String() as T
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

                ECSymmetric().encrypt<File>(parsedInput, password, tempFile, progressListener).run {
                    await()
                    getCompletionExceptionOrNull()?.let { throw it }
                }

                val fos = parsedOutputFile.outputStream()

                tempFile.inputStream().use {

                    try {
                        val passBytes = cipher.doFinal(password.asByteArray())
                        fos.write(passBytes, 0, passBytes.size)
                        val buffer = ByteArray(8192)
                        var read = it.read(buffer)
                        while (read > -1) {
                            fos.write(buffer, 0, read)
                            read = it.read(buffer)
                        }
                    } catch (e: IllegalArgumentException) {
                        throw e
                    } catch (e: IOException) {
                        throw e
                    } finally {
                        fos.flush()
                        fos.close()
                        tempFile.delete()
                    }
                    return@async parsedOutputFile as T
                }
            }
            else -> throw RuntimeException("Unable to produce result.")
        }
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
            @NotNull outputFile: File = File(Constants.DEF_DECRYPTED_FILE_PATH),
            noinline progressListener: ProgressListener? = null
    ) = GlobalScope.async {

        cipher.init(Cipher.DECRYPT_MODE, privateKey)

        val (parsedInput, parsedOutputFile, inputSize) = Pair(input, outputFile).parse(true)

        val rsaOutputSize = privateKey.size() / 8

        when (parsedInput) {

            is ByteArray -> {

                if (inputSize <= rsaOutputSize) {
                    return@async with(cipher.doFinal(parsedInput)) {
                        if (!outputFile.isDefault()) {
                            outputFile.outputStream().use {
                                it.write(this)
                                it.flush()
                            }
                            outputFile as T
                        } else asString() as T
                    }
                }

                val cipherPassBytes = ByteArray(rsaOutputSize)
                val inputStream = parsedInput.inputStream()

                inputStream.read(cipherPassBytes)

                val password = cipher.doFinal(cipherPassBytes).asString()

                val finalResult = ECSymmetric().decrypt<String>(inputStream, password).run {
                    await()
                    getCompletionExceptionOrNull()?.let { throw it }
                    getCompleted().asByteArray()
                }

                return@async if (!outputFile.isDefault()) {
                    outputFile.outputStream().use {
                        it.write(finalResult)
                        it.flush()
                    }
                    outputFile as T
                } else finalResult.asString() as T
            }

            is InputStream -> {

                with(parsedOutputFile) {
                    if (exists()) delete()
                    createNewFile()
                }

                val passCipher = ByteArray(rsaOutputSize)
                parsedInput.read(passCipher)

                val password = cipher.doFinal(passCipher).asString()

                ECSymmetric().decrypt<File>(parsedInput, password, parsedOutputFile, progressListener).run {
                    await()
                    getCompletionExceptionOrNull()?.let { throw it }
                    return@async getCompleted()
                }
            }
            else -> throw RuntimeException("Unable to produce result.")
        }
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
        object S2048 : KeySizes(2048)
        object S4096 : KeySizes(4096) // Default
    }
}

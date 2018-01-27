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
import com.pvryan.easycrypt.extensions.asByteArray
import com.pvryan.easycrypt.extensions.fromBase64
import org.jetbrains.anko.doAsync
import org.jetbrains.annotations.NotNull
import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.security.InvalidKeyException
import java.security.InvalidParameterException
import java.security.Key
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import javax.crypto.Cipher

@Suppress("KDocUnresolvedReference", "MemberVisibilityCanBePrivate", "unused")
/**
 * Secure asymmetric encryption with RSA.
 */
class ECAsymmetric {

    private val cipher: Cipher = Cipher.getInstance(Constants.ASYMMETRIC_TRANSFORMATION)

    /**
     * Encrypts the input data using RSA algorithm with OAEPwithSHA-256andMGF1Padding padding
     * and posts response to [ECResultListener.onSuccess] if successful or
     * posts error to [ECResultListener.onFailure] if failed.
     * Encryption progress is posted to [ECResultListener.onProgress].
     * Result can be a String or a File depending on the data type of [input] and parameter [outputFile].
     *
     * @param T which can be either of [String], [CharSequence],
     * [ByteArray], [InputStream], [FileInputStream], or [File]
     * @param input data to be encrypted
     * @param publicKey to encrypt the input
     * @param erl listener interface of type [ECResultListener] where result and progress will be posted
     * @param outputFile optional output file. If provided, result will be written to this file
     *
     * @exception NoSuchFileException if input is a File which does not exists or is a Directory
     * @exception InvalidParameterException if input data type is not supported
     * @exception IOException if cannot read or write to a file
     * @exception FileAlreadyExistsException if output file is provided and already exists
     */
    @JvmOverloads
    fun <T> encrypt(@NotNull input: T,
                    @NotNull publicKey: RSAPublicKey,
                    @NotNull erl: ECResultListener,
                    @NotNull outputFile: File = File(Constants.DEF_ENCRYPTED_FILE_PATH)) {

        doAsync {
            try {
                cipher.init(Cipher.ENCRYPT_MODE, publicKey as Key)
            } catch (e: InvalidKeyException) {
                erl.onFailure(Constants.ERR_INVALID_KEY, e)
                return@doAsync
            }

            when (input) {

                is ByteArrayInputStream -> encrypt(input.readBytes(), publicKey, erl, outputFile)

                is String -> encrypt(input.asByteArray(), publicKey, erl, outputFile)

                is CharSequence ->
                    encrypt(input.toString().asByteArray(), publicKey, erl, outputFile)

                is File -> {
                    if (!input.exists() || input.isDirectory) {
                        erl.onFailure(Constants.ERR_NO_SUCH_FILE, NoSuchFileException(input))
                        return@doAsync
                    }
                    val encryptedFile =
                            if (outputFile.absolutePath == Constants.DEF_ENCRYPTED_FILE_PATH)
                                File(input.absolutePath + Constants.ECRYPT_FILE_EXT)
                            else outputFile
                    encrypt(input.inputStream(), publicKey, erl, encryptedFile)
                }

                else -> performEncrypt.invoke(input, publicKey, cipher, erl, outputFile)

            }
        }
    }

    /**
     * Decrypts the input data using RSA algorithm with OAEPwithSHA-256andMGF1Padding padding
     * and posts response to [ECResultListener.onSuccess] if successful or
     * posts error to [ECResultListener.onFailure] if failed.
     * Decryption progress is posted to [ECResultListener.onProgress].
     * Result can be a String or a File depending on the data type of [input] and parameter [outputFile]
     *
     * @param input data to be decrypted. It can be of type
     * [String], [CharSequence], [ByteArray], [InputStream], [FileInputStream],or [File]
     * @param erl listener interface of type [ECResultListener] where result and progress will be posted
     * @param outputFile optional output file. If provided, result will be written to this file
     *
     * @exception NoSuchFileException if input is a File which does not exists or is a Directory
     * @exception InvalidParameterException if input data type is not supported
     * @exception IOException if cannot read or write to a file
     * @exception FileAlreadyExistsException if output file is provided and already exists
     * @exception IllegalArgumentException if input data is not in valid format
     */
    @JvmOverloads
    fun <T> decrypt(@NotNull input: T,
                    @NotNull privateKey: RSAPrivateKey,
                    @NotNull erl: ECResultListener,
                    @NotNull outputFile: File = File(Constants.DEF_DECRYPTED_FILE_PATH)) {

        doAsync {
            try {
                cipher.init(Cipher.DECRYPT_MODE, privateKey)
            } catch (e: InvalidKeyException) {
                erl.onFailure(Constants.ERR_INVALID_KEY, e)
                return@doAsync
            }

            when (input) {

                is ByteArrayInputStream -> decrypt(input.readBytes(), privateKey, erl, outputFile)

                is String -> {
                    try {
                        decrypt(input.fromBase64(), privateKey, erl, outputFile)
                    } catch (e: IllegalArgumentException) {
                        erl.onFailure(Constants.ERR_BAD_BASE64, e)
                    }
                }

                is CharSequence -> {
                    try {
                        decrypt(input.toString().fromBase64(), privateKey, erl, outputFile)
                    } catch (e: IllegalArgumentException) {
                        erl.onFailure(Constants.ERR_BAD_BASE64, e)
                    }
                }

                is File -> {
                    if (!input.exists() || input.isDirectory) {
                        erl.onFailure(Constants.ERR_NO_SUCH_FILE, NoSuchFileException(input))
                        return@doAsync
                    }
                    val decryptedFile =
                            if (outputFile.absolutePath == Constants.DEF_ENCRYPTED_FILE_PATH)
                                File(input.absolutePath + Constants.ECRYPT_FILE_EXT)
                            else outputFile
                    decrypt(input.inputStream(), privateKey, erl, decryptedFile)
                }

                else -> performDecrypt.invoke(input, privateKey, cipher, erl, outputFile)

            }
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
     * [String], [CharSequence], [ByteArray], [InputStream], [FileInputStream], or [File]
     * @param privateKey to be used for signing [input] data
     * @param erl listener interface of type [ECResultListener] where result and progress will be posted
     * @param outputFile output signature will be saved to this file
     *
     * @exception NoSuchFileException if input is a File which does not exists or is a Directory
     * @exception InvalidParameterException if input data type is not supported
     * @exception IOException if cannot read or write to a file
     * @exception FileAlreadyExistsException if output file is provided and already exists
     * @exception SignatureException if this signature algorithm is unable to process the input data provided
     */
    fun <T> sign(input: T, privateKey: RSAPrivateKey, erl: ECResultListener, outputFile: File) {

        doAsync {
            when (input) {

                is ByteArray -> sign(input.inputStream(), privateKey, erl, outputFile)

                is String -> sign(input.asByteArray().inputStream(), privateKey, erl, outputFile)

                is CharSequence ->
                    sign(input.toString().asByteArray().inputStream(), privateKey, erl, outputFile)

                is File -> {
                    if (!input.exists() || input.isDirectory) {
                        erl.onFailure(Constants.ERR_NO_SUCH_FILE, NoSuchFileException(input))
                        return@doAsync
                    }
                    sign(input.inputStream(), privateKey, erl, outputFile)
                }

                else -> performSign.invoke(input, privateKey, erl, outputFile)

            }
        }
    }

    /**
     * Verifies the input data using provided RSA public key (SHA512withRSA algorithm)
     * and posts response to [ECVerifiedListener.onSuccess] if successful or
     * posts error to [ECVerifiedListener.onFailure] if error.
     * Verification progress is posted to [ECVerifiedListener.onProgress].
     * Result is a boolean. True if data is successfully verified otherwise false
     *
     * @param input input data to be signed. It can be of type
     * [String], [CharSequence], [ByteArray], [InputStream], [FileInputStream], or [File]
     * @param publicKey to verify input data with
     * @param signature expected to match and verify input data
     * @param evl listener interface of type [ECVerifiedListener] where result and progress will be posted
     *
     * @exception NoSuchFileException if input is a File which does not exists or is a Directory
     * @exception InvalidParameterException if input data type is not supported
     * @exception IOException if cannot read from or write to a file
     * @exception FileAlreadyExistsException if output file is provided and already exists
     * @exception IllegalArgumentException if input data is not in valid format
     * @exception SignatureException if cannot use provided signature to verify input data
     */
    fun <T> verify(input: T, publicKey: RSAPublicKey, signature: File,
                   evl: ECVerifiedListener) {

        doAsync {
            when (input) {

                is ByteArray -> verify(input.inputStream(), publicKey, signature, evl)

                is String -> verify(input.asByteArray().inputStream(), publicKey, signature, evl)

                is CharSequence ->
                    verify(input.toString().asByteArray().inputStream(), publicKey, signature, evl)

                is File -> {
                    if (!input.exists() || input.isDirectory) {
                        evl.onFailure(Constants.ERR_NO_SUCH_FILE, NoSuchFileException(input))
                        return@doAsync
                    }
                    verify(input.inputStream(), publicKey, signature, evl)
                }

                else -> performVerify.invoke(input, publicKey, signature, evl)

            }
        }
    }

    /**
     * Key sizes that can be used for generating RSA key pairs
     */
    enum class KeySizes(val value: Int) {
        S_2048(2048),
        S_4096(4096) // Default
    }

}

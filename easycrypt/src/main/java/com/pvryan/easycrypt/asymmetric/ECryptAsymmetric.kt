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
import com.pvryan.easycrypt.extensions.fromBase64
import org.jetbrains.anko.doAsync
import org.jetbrains.annotations.NotNull
import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.security.InvalidParameterException
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import javax.crypto.Cipher

/**
 * Secure asymmetric encryption with RSA.
 */
class ECryptAsymmetric {

    private val ASYMMETRIC_ALGORITHM = "RSA"
    private val TRANSFORMATION = "RSA/NONE/OAEPwithSHA-256andMGF1Padding"
//    private val SIGNATURE_ALGORITHM = "SHA512withRSA"

    private val cipher = Cipher.getInstance(TRANSFORMATION)
    private val random = SecureRandom()

    /**
     * Generate a key pair with keys of specified length (default 4096) for RSA algorithm.
     *
     * @param kpl listener interface of type [ECryptRSAKeyPairListener]
     * where generated keypair will be posted
     * @param keySize of type [KeySizes] which can be 2048 or 4096 (default)
     */
    @JvmOverloads
    fun generateKeyPair(kpl: ECryptRSAKeyPairListener,
                        keySize: KeySizes = KeySizes._4096) {
        doAsync {
            val generator = KeyPairGenerator.getInstance(ASYMMETRIC_ALGORITHM)
            generator.initialize(keySize.value, random)
            val keyPair = generator.generateKeyPair()
            kpl.onSuccess(keyPair)
        }
    }

    /**
     * Encrypts the input data using RSA algorithm with OAEPwithSHA-256andMGF1Padding padding
     * and posts response to [ECryptResultListener.onSuccess] if successful or
     * posts error to [ECryptResultListener.onFailure] if failed.
     * Encryption progress is posted to [ECryptResultListener.onProgress].
     * Result can be a String or a File depending on the data type of [input] and parameter [outputFile].
     *
     * @param T which can be either of [String], [CharSequence], [ByteArray], [InputStream], or [File]
     * @param input data to be encrypted
     * @param publicKey to encrypt the input
     * @param erl listener interface of type [ECryptResultListener] where result and progress will be posted
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
                    @NotNull erl: ECryptResultListener,
                    @NotNull outputFile: File = File(Constants.DEF_ENCRYPTED_FILE_PATH)) {

        doAsync {
            cipher.init(Cipher.ENCRYPT_MODE, publicKey)

            when (input) {

                is ByteArrayInputStream -> {
                    encrypt(input.readBytes(), publicKey, erl, outputFile)
                    return@doAsync
                }

                is String -> {
                    encrypt(input.asByteArray(), publicKey, erl, outputFile)
                    return@doAsync
                }

                is CharSequence -> {
                    encrypt(input.toString().asByteArray(), publicKey, erl, outputFile)
                    return@doAsync
                }

                is File -> {
                    if (!input.exists() || input.isDirectory) {
                        erl.onFailure(Constants.MSG_NO_SUCH_FILE, NoSuchFileException(input))
                    } else {
                        val encryptedFile =
                                if (outputFile.absolutePath == Constants.DEF_ENCRYPTED_FILE_PATH)
                                    File(input.absolutePath + Constants.ECRYPT_FILE_EXT)
                                else outputFile
                        encrypt(input.inputStream(), publicKey, erl, encryptedFile)
                    }
                    return@doAsync
                }

                else -> performEncrypt.invoke(input, publicKey, cipher, erl, outputFile)

            }
        }
    }

    /**
     * Decrypts the input data using RSA algorithm with OAEPwithSHA-256andMGF1Padding padding
     * and posts response to [ECryptResultListener.onSuccess] if successful or
     * posts error to [ECryptResultListener.onFailure] if failed.
     * Decryption progress is posted to [ECryptResultListener.onProgress].
     * Result can be a String or a File depending on the data type of [input] and parameter [outputFile]
     *
     * @param input input data to be decrypted. It can be of type
     * [String], [CharSequence], [ByteArray], [InputStream], or [File]
     * @param erl listener interface of type [ECryptResultListener] where result and progress will be posted
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
                    @NotNull erl: ECryptResultListener,
                    @NotNull outputFile: File = File(Constants.DEF_DECRYPTED_FILE_PATH)) {

        doAsync {
            cipher.init(Cipher.DECRYPT_MODE, privateKey)

            when (input) {

                is ByteArrayInputStream -> {
                    decrypt(input.readBytes(), privateKey, erl, outputFile)
                    return@doAsync
                }

                is String -> {
                    try {
                        decrypt(input.fromBase64(), privateKey, erl, outputFile)
                    } catch (e: IllegalArgumentException) {
                        erl.onFailure(Constants.MSG_INVALID_INPUT_DATA, e)
                    }
                    return@doAsync
                }

                is CharSequence -> {
                    try {
                        decrypt(input.toString().fromBase64(), privateKey, erl, outputFile)
                    } catch (e: IllegalArgumentException) {
                        erl.onFailure(Constants.MSG_INVALID_INPUT_DATA, e)
                    }
                    return@doAsync
                }

                is File -> {
                    if (!input.exists() || input.isDirectory) {
                        erl.onFailure(Constants.MSG_NO_SUCH_FILE, NoSuchFileException(input))
                    } else {
                        val decryptedFile =
                                if (outputFile.absolutePath == Constants.DEF_ENCRYPTED_FILE_PATH)
                                    File(input.absolutePath + Constants.ECRYPT_FILE_EXT)
                                else outputFile
                        decrypt(input.inputStream(), privateKey, erl, decryptedFile)
                    }
                    return@doAsync
                }

                else -> performDecrypt.invoke(input, privateKey, cipher, erl, outputFile)

            }
        }
    }

    /*private fun sign(input: String, privateKey: PrivateKey): String {

        val privateSignature = Signature.getInstance(SIGNATURE_ALGORITHM)
        privateSignature.initSign(privateKey)
        privateSignature.update(input.asByteArray())

        return privateSignature.sign().toBase64String()
    }

    private fun verify(input: String, signature: String, publicKey: PublicKey): Boolean {
        val publicSignature = Signature.getInstance(SIGNATURE_ALGORITHM)
        publicSignature.initVerify(publicKey)
        publicSignature.update(input.asByteArray())

        val signatureBytes = signature.fromBase64()

        return publicSignature.verify(signatureBytes)
    }*/

    /**
     * Key sizes that can be used for generating RSA key pairs
     */
    enum class KeySizes(val value: Int) {
        _2048(2048),
        _4096(4096) // Default
    }

}

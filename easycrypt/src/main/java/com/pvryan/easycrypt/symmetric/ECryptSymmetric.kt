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

package com.pvryan.easycrypt.symmetric

import android.os.Build
import com.pvryan.easycrypt.ECryptResultListener
import com.pvryan.easycrypt.PRNGFixes
import org.jetbrains.anko.doAsync
import org.jetbrains.annotations.NotNull
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.security.InvalidKeyException
import java.security.InvalidParameterException
import java.security.spec.InvalidKeySpecException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Secure symmetric encryption with AES256.
 */
class ECryptSymmetric(transformation: ECryptTransformations
                      = ECryptTransformations.AES_CBC_PKCS7Padding) {

    private val c = Constants()

    private val cipher = Cipher.getInstance(transformation.value)

    init {
        when {
            Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT -> PRNGFixes.apply()
        }
    }

    @Throws(InvalidKeySpecException::class)
    private fun getKey(password: String = String(), salt: ByteArray): SecretKeySpec {

        val pbeKeySpec: PBEKeySpec = PBEKeySpec(
                password.trim().toCharArray(), salt, c.ITERATIONS, c.KEY_BITS_LENGTH)

        val keyFactory: SecretKeyFactory =
                SecretKeyFactory.getInstance(c.SECRET_KEY_FAC_ALGORITHM)

        val keyBytes: ByteArray = keyFactory.generateSecret(pbeKeySpec).encoded

        return SecretKeySpec(keyBytes, c.SECRET_KEY_SPEC_ALGORITHM)
    }

    /**
     * Encrypts the input data using AES algorithm in CBC mode with PKCS5Padding padding
     * and posts response to [ECryptResultListener.onSuccess] if successful or
     * posts error to [ECryptResultListener.onFailure] if failed.
     * Encryption progress is posted to [ECryptResultListener.onProgress].
     * Result can be a String or a File depending on the data type of [input] and parameter [outputFile].
     *
     * @param T which can be either of [String], [CharSequence], [ByteArray], [InputStream], or [File]
     * @param input input data to be encrypted
     * @param password password string used to encrypt input
     * @param erl listener interface of type [ECryptResultListener] where result and progress will be posted
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
    fun <T> encrypt(@NotNull input: T,
                    @NotNull password: String,
                    @NotNull erl: ECryptResultListener,
                    @NotNull outputFile: File = File(c.DEF_ENCRYPTED_FILE_PATH)) {
        doAsync {

            if (password.trim().isNullOrBlank()) {
                erl.onFailure("Password is null or blank.", InvalidKeyException())
                return@doAsync
            }

            when (input) {
                is String -> {
                    encrypt(input.toByteArray(), password, erl, outputFile)
                    return@doAsync
                }
                is CharSequence -> {
                    encrypt(input.toString().toByteArray(), password, erl, outputFile)
                    return@doAsync
                }
                is File -> {
                    if (!input.exists() || input.isDirectory) {
                        erl.onFailure(c.MSG_NO_SUCH_FILE, NoSuchFileException(input))
                    } else {
                        val encryptedFile =
                                if (outputFile.absolutePath == c.DEF_ENCRYPTED_FILE_PATH)
                                    File(input.absolutePath + c.ECRYPT_FILE_EXT)
                                else outputFile
                        encrypt(input.inputStream(), password, erl, encryptedFile)
                    }
                    return@doAsync
                }
                is InputStream -> {
                    if (outputFile.exists()) {
                        if (outputFile.absolutePath != c.DEF_ENCRYPTED_FILE_PATH) {
                            erl.onFailure(c.MSG_OUTPUT_FILE_EXISTS,
                                    FileAlreadyExistsException(outputFile))
                            return@doAsync
                        }
                        outputFile.delete()
                    }
                    outputFile.createNewFile()
                }
                is ByteArray -> {
                }
                else -> {
                    erl.onFailure(c.MSG_INPUT_TYPE_NOT_SUPPORTED, InvalidParameterException())
                    return@doAsync
                }
            }

            ECryptSymmetricEncrypt(input, password, cipher,
                    { pass, salt -> getKey(pass, salt) }, erl, outputFile)

        }
    }

    /**
     * Decrypts the input data using AES algorithm in CBC mode with PKCS5Padding padding
     * and posts response to [ECryptResultListener.onSuccess] if successful or
     * posts error to [ECryptResultListener.onFailure] if failed.
     * Decryption progress is posted to [ECryptResultListener.onProgress].
     * Result can be a String or a File depending on the data type of [input] and parameter [outputFile]
     *
     * @param input input data to be decrypted. It can be of type
     * [String], [CharSequence], [ByteArray], [InputStream], or [File]
     * @param password password string used to encrypt input
     * @param erl listener interface of type [ECryptResultListener] where result and progress will be posted
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
    fun <T> decrypt(@NotNull input: T,
                    @NotNull password: String,
                    @NotNull erl: ECryptResultListener,
                    @NotNull outputFile: File = File(c.DEF_DECRYPTED_FILE_PATH)) {
        doAsync {
            if (password.trim().isNullOrBlank()) {
                erl.onFailure("Password is null or blank.", InvalidKeyException())
                return@doAsync
            }

            when (input) {

                is String -> {
                    decrypt(input.toByteArray(), password, erl, outputFile)
                }

                is CharSequence -> {
                    decrypt(input.toString().toByteArray(), password, erl, outputFile)
                }

                is File -> {

                    if (!input.exists() || input.isDirectory) {
                        erl.onFailure(c.MSG_NO_SUCH_FILE, NoSuchFileException(input))
                        return@doAsync
                    }

                    val decryptedFile =
                            if (outputFile.absolutePath == c.DEF_DECRYPTED_FILE_PATH)
                                File(input.absoluteFile.toString().removeSuffix(c.ECRYPT_FILE_EXT))
                            else outputFile

                    decrypt(input.inputStream(), password, erl, decryptedFile)
                }

                else -> ECryptSymmetricDecrypt(input, password, cipher,
                        { pass, salt -> getKey(pass, salt) }, erl, outputFile)

            }
        }
    }
}

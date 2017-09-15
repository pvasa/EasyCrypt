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
import com.pvryan.easycrypt.Constants
import com.pvryan.easycrypt.ECResultListener
import com.pvryan.easycrypt.PRNGFixes
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
class ECSymmetric(transformation: ECSymmetricTransformations
                  = ECSymmetricTransformations.AES_CBC_PKCS7Padding) {

    private val cipher = Cipher.getInstance(transformation.value)

    init {
        when {
            Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT -> PRNGFixes.apply()
        }
    }

    @Throws(InvalidKeySpecException::class)
    private fun getKey(password: String = String(), salt: ByteArray): SecretKeySpec {
        val pbeKeySpec = PBEKeySpec(password.trim().toCharArray(),
                salt, Constants.ITERATIONS, Constants.KEY_BITS_LENGTH)
        val keyFactory: SecretKeyFactory =
                SecretKeyFactory.getInstance(Constants.SECRET_KEY_FAC_ALGORITHM)
        val keyBytes: ByteArray = keyFactory.generateSecret(pbeKeySpec).encoded
        return SecretKeySpec(keyBytes, Constants.SECRET_KEY_SPEC_ALGORITHM)
    }

    /**
     * Symmetrically encrypts the input data using AES algorithm in CBC mode with PKCS7Padding padding
     * and posts response to [ECResultListener.onSuccess] if successful or
     * posts error to [ECResultListener.onFailure] if failed.
     * Encryption progress is posted to [ECResultListener.onProgress].
     * Result can be a String or a File depending on the data type of [input] and parameter [outputFile].
     *
     * @param T which can be either of [String], [CharSequence],
     * [ByteArray], [InputStream], [FileInputStream], or [File]
     * @param input data to be encrypted
     * @param password string used to encrypt input
     * @param erl listener interface of type [ECResultListener] where result and progress will be posted
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
                    @NotNull erl: ECResultListener,
                    @NotNull outputFile: File = File(Constants.DEF_ENCRYPTED_FILE_PATH)) {
        doAsync {

            val tPass = password.trim()

            /*if (tPass.isNullOrBlank()) {
                erl.onFailure("Password is null or blank.", InvalidKeyException())
                return@doAsync
            }*/

            when (input) {

                is String -> encrypt(input.asByteArray(), password, erl, outputFile)

                is CharSequence ->
                    encrypt(input.toString().asByteArray(), password, erl, outputFile)

                is ByteArrayInputStream -> encrypt(input.readBytes(), password, erl, outputFile)

                is File -> {
                    if (!input.exists() || input.isDirectory) {
                        erl.onFailure(Constants.ERR_NO_SUCH_FILE, NoSuchFileException(input))
                        return@doAsync
                    }
                    val encryptedFile =
                            if (outputFile.absolutePath == Constants.DEF_ENCRYPTED_FILE_PATH)
                                File(input.absolutePath + Constants.ECRYPT_FILE_EXT)
                            else outputFile
                    encrypt(input.inputStream(), password, erl, encryptedFile)
                }

                else -> performEncrypt.invoke(input, tPass, cipher,
                        { pass, salt -> getKey(pass, salt) }, erl, outputFile)
            }
        }
    }

    /**
     * Symmetrically decrypts the input data using AES algorithm in CBC mode with PKCS7Padding padding
     * and posts response to [ECResultListener.onSuccess] if successful or
     * posts error to [ECResultListener.onFailure] if failed.
     * Decryption progress is posted to [ECResultListener.onProgress].
     * Result can be a String or a File depending on the data type of [input] and parameter [outputFile]
     *
     * @param input input data to be decrypted. It can be of type
     * [String], [CharSequence], [ByteArray], [InputStream], [FileInputStream], or [File]
     * @param password password string used to performEncrypt input
     * @param erl listener interface of type [ECResultListener] where result and progress will be posted
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
                    @NotNull erl: ECResultListener,
                    @NotNull outputFile: File = File(Constants.DEF_DECRYPTED_FILE_PATH)) {
        doAsync {

            val tPass = password.trim()

            /*if (tPass.isNullOrBlank()) {
                erl.onFailure("Password is null or blank.", InvalidKeyException())
                return@doAsync
            }*/

            when (input) {

                is String -> decrypt(input.fromBase64().inputStream(), password, erl, outputFile)

                is CharSequence -> decrypt(input.toString().fromBase64().inputStream(),
                        password, erl, outputFile)

                is ByteArray -> decrypt(input.inputStream(), password, erl, outputFile)

                is File -> {

                    if (!input.exists() || input.isDirectory) {
                        erl.onFailure(Constants.ERR_NO_SUCH_FILE, NoSuchFileException(input))
                        return@doAsync
                    }

                    val decryptedFile =
                            if (outputFile.absolutePath == Constants.DEF_DECRYPTED_FILE_PATH)
                                File(input.absoluteFile.toString().removeSuffix(Constants.ECRYPT_FILE_EXT))
                            else outputFile

                    decrypt(input.inputStream(), password, erl, decryptedFile)
                }

                else -> performDecrypt.invoke(input, tPass, cipher,
                        { pass, salt -> getKey(pass, salt) }, erl, outputFile)

            }
        }
    }
}

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
import com.pvryan.easycrypt.extensions.asString
import com.pvryan.easycrypt.extensions.generateRandom
import com.pvryan.easycrypt.extensions.toBase64
import com.pvryan.easycrypt.extensions.toBase64String
import com.pvryan.easycrypt.parse
import kotlinx.coroutines.experimental.GlobalScope
import kotlinx.coroutines.experimental.async
import org.jetbrains.annotations.NotNull
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStream
import java.security.InvalidKeyException
import java.security.InvalidParameterException
import java.security.spec.InvalidKeySpecException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.IllegalBlockSizeException
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

typealias ProgressListener = (newBytes: Int, bytesProcessed: Long, totalBytes: Long) -> Unit

fun File.isDefault(): Boolean =
        absolutePath == Constants.DEF_ENCRYPTED_FILE_PATH
                || absolutePath == Constants.DEF_DECRYPTED_FILE_PATH

@Throws(InvalidKeySpecException::class)
@PublishedApi
internal fun getKey(password: String = String(), salt: ByteArray): SecretKeySpec {
    val pbeKeySpec = PBEKeySpec(password.trim().toCharArray(),
            salt, Constants.ITERATIONS, Constants.KEY_BITS_LENGTH)
    val keyFactory: SecretKeyFactory =
            SecretKeyFactory.getInstance(Constants.SECRET_KEY_FAC_ALGORITHM)
    val keyBytes: ByteArray = keyFactory.generateSecret(pbeKeySpec).encoded
    return SecretKeySpec(keyBytes, Constants.SECRET_KEY_SPEC_ALGORITHM)
}

/**
 * Secure symmetric encryption with AES256.
 */
open class ECSymmetric(
        transformation: ECSymmetricTransformations = ECSymmetricTransformations.AesCbcPkcs7Padding
) {
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
    open fun <T> encrypt(
            @NotNull input: Any,
            @NotNull password: String,
            @NotNull outputFile: File = File(Constants.DEF_ENCRYPTED_FILE_PATH),
            progressListener: ProgressListener? = null
    ) = GlobalScope.async {

        val (parsedInput, parsedOutputFile) = Pair(input, outputFile).parse(true)

        val salt = ByteArray(Constants.SALT_BYTES_LENGTH).generateRandom()
        val keySpec = getKey(password, salt)
        val iv = ByteArray(cipher.blockSize).generateRandom()
        val ivParams = IvParameterSpec(iv)

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParams)

        when (parsedInput) {

            is ByteArray -> {

                val result = iv.plus(salt).plus(cipher.doFinal(parsedInput))

                with(result) {
                    return@async if (!parsedOutputFile.isDefault()) {
                        parsedOutputFile.outputStream().use {
                            it.write(toBase64())
                            it.flush()
                        }
                        parsedOutputFile as T
                    } else toBase64String() as T
                }
            }

            is FileInputStream -> {

                val fos = with(parsedOutputFile) {
                    if (exists()) delete()
                    createNewFile()
                    outputStream()
                }

                try {
                    fos.write(iv)
                    fos.write(salt)
                } catch (e: IOException) {
                    fos.flush()
                    fos.close()
                    parsedInput.close()
                    parsedOutputFile.delete()
                    throw e
                }

                val cos = CipherOutputStream(fos, cipher)

                try {
                    val size = parsedInput.channel.size()
                    val buffer = ByteArray(8192)
                    var bytesCopied: Long = 0
                    var read = parsedInput.read(buffer)

                    while (read > -1) {
                        cos.write(buffer, 0, read)
                        bytesCopied += read
                        progressListener?.invoke(read, bytesCopied, size)
                        read = parsedInput.read(buffer)
                    }
                } catch (e: IOException) {
                    parsedOutputFile.delete()
                    throw e
                } finally {
                    cos.flush()
                    cos.close()
                    parsedInput.close()
                }
                return@async parsedOutputFile as T
            }
        }
        throw RuntimeException("Unable to produce result.")
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
    open fun <T> decrypt(
            @NotNull input: Any,
            @NotNull password: String,
            @NotNull outputFile: File = File(Constants.DEF_DECRYPTED_FILE_PATH),
            progressListener: ProgressListener? = null
    ) = GlobalScope.async {

        val (parsedInput, parsedOutputFile) = Pair(input, outputFile).parse(false)

        val ivBytesLength = cipher.blockSize

        when (parsedInput) {

            is ByteArray -> {

                val iv = parsedInput.copyOfRange(0, ivBytesLength - 1)
                val salt = parsedInput.copyOfRange(ivBytesLength, Constants.SALT_BYTES_LENGTH - 1)

                if (ivBytesLength != iv.size
                        || Constants.SALT_BYTES_LENGTH != salt.size) {
                    throw BadPaddingException(Constants.ERR_INVALID_INPUT_DATA)
                }

                val ivParams = IvParameterSpec(iv)
                val key = getKey(password, salt)

                cipher.init(Cipher.DECRYPT_MODE, key, ivParams)

                with(parsedInput.readBytes()) {
                    return@async if (!parsedOutputFile.isDefault()) try {
                        parsedOutputFile.outputStream().use {
                            it.write(this)
                            it.flush()
                        }
                        parsedOutputFile as T
                    } catch (e: IOException) {
                        throw IOException(Constants.ERR_CANNOT_WRITE, e)
                    } else asString()
                }
            }

            is ByteArrayInputStream -> {

                val iv = ByteArray(ivBytesLength)
                val salt = ByteArray(Constants.SALT_BYTES_LENGTH)

                if (ivBytesLength != parsedInput.read(iv)
                        || Constants.SALT_BYTES_LENGTH != parsedInput.read(salt)) {
                    parsedInput.close()
                    throw BadPaddingException(Constants.ERR_INVALID_INPUT_DATA)
                }

                val ivParams = IvParameterSpec(iv)
                val key = getKey(password, salt)

                try {
                    cipher.init(Cipher.DECRYPT_MODE, key, ivParams)

                    with(parsedInput.readBytes()) {
                        return@async if (!parsedOutputFile.isDefault()) try {
                            parsedOutputFile.outputStream().use {
                                it.write(this)
                                it.flush()
                            }
                            parsedOutputFile as T
                        } catch (e: IOException) {
                            throw IOException(Constants.ERR_CANNOT_WRITE, e)
                        } else asString() as T
                    }
                } catch (e: BadPaddingException) {
                    throw e
                } catch (e: IllegalBlockSizeException) {
                    throw e
                } finally {
                    parsedInput.close()
                }
            }

            is FileInputStream -> {

                var cis: CipherInputStream? = null

                val fos = with(parsedOutputFile) {
                    if (exists()) delete()
                    createNewFile()
                    outputStream()
                }

                val iv = ByteArray(ivBytesLength)
                val salt = ByteArray(Constants.SALT_BYTES_LENGTH)

                try {
                    if (ivBytesLength != parsedInput.read(iv) ||
                            Constants.SALT_BYTES_LENGTH != parsedInput.read(salt)) {
                        parsedInput.close()
                        throw BadPaddingException(Constants.ERR_INVALID_INPUT_DATA)
                    }
                } catch (e: IOException) {
                    parsedInput.close()
                    throw e
                }

                val key = getKey(password, salt)
                val ivParams = IvParameterSpec(iv)

                cipher.init(Cipher.DECRYPT_MODE, key, ivParams)

                try {
                    val size = parsedInput.channel.size()
                    cis = CipherInputStream(parsedInput, cipher)

                    val buffer = ByteArray(8192)
                    var bytesCopied: Long = 0

                    var read = cis.read(buffer)
                    while (read > -1) {
                        fos.write(buffer, 0, read)
                        bytesCopied += read
                        progressListener?.invoke(read, bytesCopied, size)
                        read = cis.read(buffer)
                    }
                } catch (e: IOException) {
                    parsedOutputFile.delete()
                    throw e
                } finally {
                    fos.flush()
                    fos.close()
                    cis?.close()
                }
                return@async parsedOutputFile as T
            }
        }
        throw RuntimeException("Unable to produce result.")
    }
}

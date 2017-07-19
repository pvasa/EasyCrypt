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

package com.pvryan.easycrypt

import android.os.Build
import android.os.Environment
import com.pvryan.easycrypt.extensions.*
import com.pvryan.easycrypt.randomorg.RandomOrgApis
import com.pvryan.easycrypt.randomorg.RandomOrgRequest
import com.pvryan.easycrypt.randomorg.RandomOrgResponse
import org.jetbrains.anko.doAsync
import org.jetbrains.annotations.NotNull
import retrofit2.Call
import retrofit2.Callback
import retrofit2.Response
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.security.InvalidKeyException
import java.security.InvalidParameterException
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.spec.InvalidKeySpecException
import javax.crypto.*
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec


/**
 * It provides methods to [encrypt], [decrypt], and [hash] data
 */
class ECrypt {

    private val TRANSFORMATION = "AES/CBC/PKCS5Padding"
    private var SECRET_KEY_FAC_ALGORITHM = "PBKDF2WithHmacSHA1"
    private val SECRET_KEY_SPEC_ALGORITHM = "AES"

    private val cipher = Cipher.getInstance(TRANSFORMATION)
    private val random: SecureRandom

    private val KEY_BITS_LENGTH = 256
    private val IV_BYTES_LENGTH = cipher.blockSize
    private val SALT_BYTES_LENGTH = KEY_BITS_LENGTH / 8
    private val ITERATIONS = 10000

    private val HASH_FILE_EXT = ".txt"
    private val ECRYPT_FILE_EXT = ".ecrypt"

    private val HASH_FILE_NAME = "HashOfFile"
    private val ENCRYPTED_FILE_NAME = "EncryptedFile"
    private val DECRYPTED_FILE_NAME = "DecryptedFile"

    private val DEF_HASH_FILE_PATH =
            Environment.getExternalStorageDirectory().absolutePath +
                    File.separator + HASH_FILE_NAME + HASH_FILE_EXT
    private val DEF_ENCRYPTED_FILE_PATH =
            Environment.getExternalStorageDirectory().absolutePath +
                    File.separator + ENCRYPTED_FILE_NAME + ECRYPT_FILE_EXT
    private val DEF_DECRYPTED_FILE_PATH =
            Environment.getExternalStorageDirectory().absolutePath +
                    File.separator + DECRYPTED_FILE_NAME + ECRYPT_FILE_EXT

    private val MSG_INPUT_TYPE_NOT_SUPPORTED = "Input type not supported."
    private val MSG_INVALID_INPUT_DATA = "Invalid input data."
    private val MSG_NO_SUCH_FILE = "File does not exist."
    private val MSG_CANNOT_WRITE = "Cannot write to file."
    private val MSG_CANNOT_READ = "Cannot read from file."
    private val MSG_OUTPUT_FILE_EXISTS = "Output file already exists."

    private val STANDARD_SYMBOLS =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                    "abcdefghijklmnopqrstuvwxyz" +
                    "0123456789"

    init {
        when {
            Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT -> PRNGFixes.apply()
            Build.VERSION.SDK_INT >= 26 -> SECRET_KEY_FAC_ALGORITHM = "PBEwithHmacSHA512AndAES_256"
        }
        random = SecureRandom()
    }

    /**
     * Generate pseudo-random password using Java's [SecureRandom] number generator.
     *
     * @param length of password to be generated
     * @param symbols to be used in the password
     *
     * @return [String] password of specified [length]
     *
     * @throws InvalidParameterException when length is less than 1
     */
    @Throws(InvalidParameterException::class)
    @JvmOverloads
    fun genSecureRandomPassword(length: Int,
                                symbols: CharArray = STANDARD_SYMBOLS.toCharArray()): String {

        if (length < 1) throw InvalidParameterException(
                "Invalid password length. Only positive length allowed.")

        val password = CharArray(length)
        for (i in 0..length - 1) {
            password[i] = symbols[random.nextInt(symbols.size - 1)]
        }
        return password.joinToString("")
    }

    /**
     * Generate true random password using random.org service
     * and posts response to [ECryptPasswordListener.onSuccess] if successful or
     * posts error to [ECryptPasswordListener.onFailure] if failed.
     * Result is a [String] password of specified [length].
     *
     * @param length of password to be generated
     * @param randomOrgApiKey provided by api.random.org/api-keys/beta
     * @param resultListener listener interface of type [ECryptPasswordListener] where generated password will be posted
     */
    fun genRandomOrgPassword(length: Int, randomOrgApiKey: String,
                             resultListener: ECryptPasswordListener) {

        if (length < 2) {
            resultListener.onFailure(
                    "Invalid length.",
                    InvalidParameterException("Password length cannot be less than 2."))
            return
        }

        doAsync {

            val retrofit = Retrofit.Builder().baseUrl(RandomOrgApis.BASE_URL)
                    .addConverterFactory(GsonConverterFactory.create()).build()

            val randomOrgApis: RandomOrgApis = retrofit.create(RandomOrgApis::class.java)

            val params = RandomOrgRequest.Params(apiKey = randomOrgApiKey, n = length / 2)
            val postData = RandomOrgRequest(params = params)

            randomOrgApis.request(postData).enqueue(object : Callback<RandomOrgResponse> {

                override fun onFailure(call: Call<RandomOrgResponse>, t: Throwable) {
                    resultListener.onFailure(t.localizedMessage, Exception(t))
                }

                override fun onResponse(call: Call<RandomOrgResponse>, response: Response<RandomOrgResponse>) {

                    if (HttpURLConnection.HTTP_OK == response.code()) {

                        val body = response.body()

                        if (body != null) {
                            val randomKeyArray = body.result.random.data
                            val randomKeyHex = StringBuilder()
                            for (i in 0..(randomKeyArray.size() - 1)) {
                                randomKeyHex.append(randomKeyArray[i].toString().replace("\"", "", true))
                            }
                            resultListener.onSuccess(randomKeyHex.toString())
                        } else {
                            resultListener.onFailure("Random.org error.",
                                    Exception(response.errorBody()?.string()
                                            ?: "Null response from Random.org. Please try again."))
                        }
                    } else {
                        resultListener.onFailure("Response code ${response.code()}",
                                Exception(response.errorBody()?.string() ?:
                                        "Some error occurred at Random.org. Please try again."))
                    }
                }
            })
        }
    }

    @Throws(InvalidKeySpecException::class)
    private fun getKey(password: String = String(), salt: ByteArray): SecretKeySpec {

        val pbeKeySpec: PBEKeySpec = PBEKeySpec(
                password.trim().toCharArray(), salt, ITERATIONS, KEY_BITS_LENGTH)

        val keyFactory: SecretKeyFactory =
                SecretKeyFactory.getInstance(SECRET_KEY_FAC_ALGORITHM)

        val keyBytes: ByteArray = keyFactory.generateSecret(pbeKeySpec).encoded

        return SecretKeySpec(keyBytes, SECRET_KEY_SPEC_ALGORITHM)
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
    @Suppress("UNCHECKED_CAST")
    @JvmOverloads
    fun <T> encrypt(@NotNull input: T,
                    @NotNull password: String,
                    @NotNull erl: ECryptResultListener,
                    @NotNull outputFile: File = File(DEF_ENCRYPTED_FILE_PATH)) {
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
                        erl.onFailure(MSG_NO_SUCH_FILE, NoSuchFileException(input))
                    } else {
                        val encryptedFile =
                                if (outputFile.absolutePath == DEF_ENCRYPTED_FILE_PATH)
                                    File(input.absolutePath + ECRYPT_FILE_EXT)
                                else outputFile
                        encrypt(input.inputStream(), password, erl, encryptedFile)
                    }
                    return@doAsync
                }
                is InputStream -> {
                    if (outputFile.exists()) {
                        if (outputFile.absolutePath != DEF_ENCRYPTED_FILE_PATH) {
                            erl.onFailure(MSG_OUTPUT_FILE_EXISTS,
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
                    erl.onFailure(MSG_INPUT_TYPE_NOT_SUPPORTED, InvalidParameterException())
                    return@doAsync
                }
            }

            val salt = ByteArray(SALT_BYTES_LENGTH)
            random.nextBytes(salt)

            val keySpec = getKey(password, salt)

            val iv = ByteArray(IV_BYTES_LENGTH)
            random.nextBytes(iv)
            val ivParams = IvParameterSpec(iv)

            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParams)

            when (input) {

                is ByteArray -> {

                    try {
                        val output = iv.plus(salt).plus(cipher.doFinal(input))

                        if (outputFile.absolutePath != DEF_ENCRYPTED_FILE_PATH) {

                            if (outputFile.exists()) {
                                erl.onFailure(MSG_OUTPUT_FILE_EXISTS,
                                        FileAlreadyExistsException(outputFile))
                                return@doAsync
                            }

                            outputFile.outputStream().use {
                                it.write(output.toBase64())
                                it.flush()
                                erl.onSuccess(outputFile as T)
                            }
                        } else {
                            erl.onSuccess(output.toBase64String())
                        }
                    } catch (e: IOException) {
                        erl.onFailure(MSG_CANNOT_WRITE, e)
                    }
                }

                is InputStream -> {

                    val fos = outputFile.outputStream()
                    var cos = CipherOutputStream(fos, cipher)

                    try {
                        fos.write(iv)
                        fos.write(salt)
                        cos = CipherOutputStream(fos, cipher)

                        val buffer = ByteArray(8192)
                        var bytesCopied: Long = 0
                        var read = input.read(buffer)

                        while (read > -1) {
                            cos.write(buffer, 0, read)
                            bytesCopied += read
                            erl.onProgress(read, bytesCopied)
                            read = input.read(buffer)
                        }

                        erl.onSuccess(outputFile as T)

                    } catch (e: IOException) {
                        outputFile.delete()
                        erl.onFailure(MSG_CANNOT_WRITE, e)
                    } finally {
                        cos.flush()
                        cos.close()
                        input.close()
                    }
                }
            }
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
    @Suppress("UNCHECKED_CAST")
    @JvmOverloads
    fun <T> decrypt(@NotNull input: T,
                    @NotNull password: String,
                    @NotNull erl: ECryptResultListener,
                    @NotNull outputFile: File = File(DEF_DECRYPTED_FILE_PATH)) {
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
                        erl.onFailure(MSG_NO_SUCH_FILE, NoSuchFileException(input))
                        return@doAsync
                    }

                    val decryptedFile =
                            if (outputFile.absolutePath == DEF_DECRYPTED_FILE_PATH)
                                File(input.absoluteFile.toString().removeSuffix(ECRYPT_FILE_EXT))
                            else outputFile

                    decrypt(input.inputStream(), password, erl, decryptedFile)
                }

                is ByteArray -> {

                    val decodedBytes: ByteArray = try {
                        input.fromBase64()
                    } catch (e: IllegalArgumentException) {
                        erl.onFailure(MSG_INVALID_INPUT_DATA, e)
                        byteArrayOf()
                        return@doAsync
                    }

                    decodedBytes.inputStream().use {

                        val IV = ByteArray(IV_BYTES_LENGTH)
                        val salt = ByteArray(SALT_BYTES_LENGTH)

                        if (IV_BYTES_LENGTH != it.read(IV) || SALT_BYTES_LENGTH != it.read(salt)) {
                            erl.onFailure(MSG_INVALID_INPUT_DATA, BadPaddingException())
                            return@doAsync
                        }

                        val ivParams = IvParameterSpec(IV)
                        val key = getKey(password, salt)

                        try {
                            cipher.init(Cipher.DECRYPT_MODE, key, ivParams)

                            val secureBytes = it.readBytes()
                            val plainBytes = cipher.doFinal(secureBytes)

                            if (outputFile.absolutePath != DEF_DECRYPTED_FILE_PATH) {
                                outputFile.outputStream().use {
                                    it.write(plainBytes)
                                    it.flush()
                                }
                                erl.onSuccess(outputFile as T)
                            } else {
                                erl.onSuccess(plainBytes.asString() as T)
                            }
                        } catch (e: BadPaddingException) {
                            erl.onFailure(MSG_INVALID_INPUT_DATA, e)
                        } catch (e: IllegalBlockSizeException) {
                            erl.onFailure(MSG_INVALID_INPUT_DATA, e)
                        }
                    }
                }

                is InputStream -> {

                    if (outputFile.exists()) {
                        if (outputFile.absolutePath != DEF_DECRYPTED_FILE_PATH) {
                            erl.onFailure(MSG_OUTPUT_FILE_EXISTS,
                                    FileAlreadyExistsException(outputFile))
                            return@doAsync
                        }
                        outputFile.delete()
                    }
                    outputFile.createNewFile()

                    var cis: CipherInputStream? = null
                    val fos = outputFile.outputStream()

                    val iv = ByteArray(IV_BYTES_LENGTH)
                    val salt = ByteArray(SALT_BYTES_LENGTH)

                    try {
                        if (IV_BYTES_LENGTH != input.read(iv) ||
                                SALT_BYTES_LENGTH != input.read(salt)) {
                            erl.onFailure(MSG_INVALID_INPUT_DATA, BadPaddingException())
                            return@doAsync
                        }
                    } catch (e: IOException) {
                        erl.onFailure(MSG_CANNOT_READ, e)
                        return@doAsync
                    }

                    val key = getKey(password, salt)
                    val ivParams = IvParameterSpec(iv)

                    cipher.init(Cipher.DECRYPT_MODE, key, ivParams)

                    try {
                        cis = CipherInputStream(input, cipher)

                        val buffer = ByteArray(8192)
                        var bytesCopied: Long = 0

                        var read = cis.read(buffer)
                        while (read > -1) {
                            fos.write(buffer, 0, read)
                            bytesCopied += read
                            erl.onProgress(read, bytesCopied)
                            read = cis.read(buffer)
                        }

                        erl.onSuccess(outputFile as T)

                    } catch (e: IOException) {
                        outputFile.delete()
                        erl.onFailure(MSG_CANNOT_WRITE, e)
                    } finally {
                        fos.flush()
                        fos.close()
                        cis?.close()
                    }
                }

                else -> erl.onFailure(MSG_INPUT_TYPE_NOT_SUPPORTED, InvalidParameterException())

            }
        }
    }

    /**
     * Decrypts the input data using AES algorithm in CBC mode with PKCS5Padding padding
     * and posts response to [ECryptResultListener.onSuccess] if successful or
     * posts error to [ECryptResultListener.onFailure] if failed.
     * Hashing progress is posted to [ECryptResultListener.onProgress].
     * Result is either returned as a Hex string or Hex string returned in [outputFile] if provided.
     *
     * @param input input data to be hashed. It can be of type
     * [String], [CharSequence], [ByteArray], [InputStream], or [File]
     * @param erl listener interface of type ECryptResultListener where result and progress will be posted
     * @param outputFile optional output file. If provided, result will be written to this file
     *
     * @exception NoSuchFileException if input is a File which does not exists or is a Directory
     * @exception InvalidParameterException if input data type is not supported
     * @exception IOException if cannot read or write to a file
     * @exception FileAlreadyExistsException if output file is provided and already exists
     */
    @JvmOverloads
    fun <T> hash(@NotNull input: T,
                 @NotNull algorithm: ECryptHashAlgorithms = ECryptHashAlgorithms.SHA_512,
                 @NotNull erl: ECryptResultListener,
                 @NotNull outputFile: File = File(DEF_HASH_FILE_PATH)) {
        doAsync {

            val digest: MessageDigest = MessageDigest.getInstance(algorithm.value)

            when (input) {

                is String -> {
                    hash(input.toByteArray().inputStream(), algorithm, erl, outputFile)
                }

                is CharSequence -> {
                    hash(input.toString().toByteArray().inputStream(), algorithm, erl, outputFile)
                }

                is File -> {
                    hash(input.inputStream(), algorithm, erl, outputFile)
                }

                is ByteArray -> {
                    val hash = digest.digest(input).asHexString()
                    if (outputFile.absolutePath != DEF_HASH_FILE_PATH) {
                        outputFile.outputStream().use {
                            it.write(hash.toByteArray())
                            it.flush()
                        }
                        erl.onSuccess(outputFile)
                    } else {
                        erl.onSuccess(hash)
                    }
                }

                is InputStream -> {

                    val buffer = ByteArray(8192)

                    if (input.available() <= buffer.size) {
                        hash(input.readBytes(), algorithm, erl, outputFile)
                        return@doAsync
                    }

                    try {

                        var bytesCopied: Long = 0
                        var read = input.read(buffer)
                        while (read > -1) {
                            digest.update(buffer, 0, read)
                            bytesCopied += read
                            erl.onProgress(read, bytesCopied)
                            read = input.read(buffer)
                        }

                        val hash = digest.digest().asHexString()

                        if (outputFile.absolutePath != DEF_HASH_FILE_PATH) {
                            outputFile.outputStream().use {
                                it.write(hash.toByteArray())
                                it.flush()
                            }
                            erl.onSuccess(outputFile)
                        } else {
                            erl.onSuccess(hash)
                        }

                    } catch (e: IOException) {
                        erl.onFailure(MSG_CANNOT_READ, e)
                    } finally {
                        input.close()
                    }
                }

                else -> erl.onFailure(MSG_INPUT_TYPE_NOT_SUPPORTED, InvalidParameterException())
            }
        }
    }

    /**
     * Interface where result is posted by [encrypt], [decrypt], and [hash]
     */
    interface ECryptResultListener {
        /**
         * @param newBytes number of new bytes processed
         * @param bytesProcessed total number of bytes processed
         */
        fun onProgress(newBytes: Int, bytesProcessed: Long) {}

        /**
         * @param result of the methods [encrypt], [decrypt], or [hash]
         */
        fun <T> onSuccess(result: T)

        /**
         * @param message on failure
         * @param e exception thrown by called method
         */
        fun onFailure(message: String, e: Exception)
    }

    /**
     * Interface where result is posted by [genRandomOrgPassword]
     */
    interface ECryptPasswordListener {

        /**
         * @param password generated by [genRandomOrgPassword]
         */
        fun onSuccess(password: String)

        /**
         * @param message on failure
         * @param e exception thrown by called method
         */
        fun onFailure(message: String, e: Exception)

    }

}

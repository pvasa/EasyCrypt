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
import org.jetbrains.anko.AnkoLogger
import org.jetbrains.anko.doAsync
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStream
import java.security.InvalidParameterException
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.*
import javax.crypto.spec.IvParameterSpec

class ECrypt : AnkoLogger {

    val KEY_BITS_LENGTH = 256
    private val SALT_BYTES_LENGTH = KEY_BITS_LENGTH / 8
    val ITERATIONS = 10000

    private val TRANSFORMATION = "AES/CBC/PKCS5Padding"
    var SECRET_KEY_FAC_ALGORITHM = "PBKDF2WithHmacSHA1"
    val SECRET_KEY_SPEC_ALGORITHM = "AES"

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

    private val MSG_INVALID_INPUT_TYPE = "Invalid input type."
    private val MSG_INVALID_INPUT_DATA = "Invalid input data."
    private val MSG_NO_SUCH_FILE = "File does not exist."
    private val MSG_CANNOT_WRITE = "Cannot write to file."
    private val MSG_CANNOT_READ = "Cannot read from file."
    private val MSG_OUTPUT_FILE_EXISTS = "Output file already exists."

    private val cipher = Cipher.getInstance(TRANSFORMATION)
    private val random = SecureRandom()

    init {
        if (Build.VERSION.SDK_INT >= 26) {
            SECRET_KEY_FAC_ALGORITHM = "PBEwithHmacSHA512AndAES_256"
        }
    }

    @Suppress("UNCHECKED_CAST")
    fun <T> encrypt(input: T, password: String, erl: ECryptResultListener,
                    outputFile: File = File(DEF_ENCRYPTED_FILE_PATH)) {
        doAsync {

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
                is FileInputStream -> {
                }
                is ByteArray -> {
                }
                else -> erl.onFailure(MSG_INVALID_INPUT_TYPE, InvalidParameterException())
            }

            val salt = ByteArray(SALT_BYTES_LENGTH)
            random.nextBytes(salt)

            val keySpec = getKey(password, salt)

            val iv = ByteArray(cipher.blockSize)
            random.nextBytes(iv)
            val ivParams = IvParameterSpec(iv)

            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParams)

            when (input) {

                is ByteArray -> {

                    try {
                        if (outputFile.absolutePath != DEF_ENCRYPTED_FILE_PATH) {
                            outputFile.outputStream().use {
                                val secureBytes = cipher.doFinal(input)

                                it.write(iv.plus(salt).plus(secureBytes).toBase64())
                                it.flush()

                                erl.onSuccess(outputFile as T)
                            }
                        } else {
                            val secureBytes = cipher.doFinal(input)
                            erl.onSuccess(iv.plus(salt).plus(secureBytes).toBase64String())
                        }
                    } catch (e: IOException) {
                        erl.onFailure(MSG_CANNOT_WRITE, e)
                    }
                }

                is InputStream -> {
                    val fos = outputFile.outputStream()
                    var cos = CipherOutputStream(fos, cipher)
                    try {
                        if (outputFile.exists()) {
                            if (outputFile.absolutePath != DEF_ENCRYPTED_FILE_PATH) {
                                erl.onFailure(MSG_OUTPUT_FILE_EXISTS,
                                        FileAlreadyExistsException(outputFile))
                                return@doAsync
                            }
                            outputFile.delete()
                        }
                        outputFile.createNewFile()

                        fos.write(iv)
                        fos.write(salt)
                        cos = CipherOutputStream(fos, cipher)

                        val buffer = ByteArray(8192)
                        var wrote = 0
                        while ({ wrote = input.read(buffer); wrote }() > 0) {
                            cos.write(buffer)
                            erl.onProgress(wrote)
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

    @Suppress("UNCHECKED_CAST")
    fun <T> decrypt(input: T, password: String, erl: ECryptResultListener,
                    outputFile: File = File(DEF_DECRYPTED_FILE_PATH)) {
        doAsync {

            when (input) {

                is String -> {
                    decrypt(input.toByteArray(), password, erl, outputFile)
                    return@doAsync
                }

                is CharSequence -> {
                    decrypt(input.toString().toByteArray(), password, erl, outputFile)
                    return@doAsync
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

                        val IV = ByteArray(cipher.blockSize)
                        val salt = ByteArray(SALT_BYTES_LENGTH)

                        if (cipher.blockSize != it.read(IV) || SALT_BYTES_LENGTH != it.read(salt)) {
                            erl.onFailure(MSG_INVALID_INPUT_DATA, BadPaddingException())
                            return@doAsync
                        }

                        val ivParams = IvParameterSpec(IV)
                        val key = getKey(password, salt)
                        cipher.init(Cipher.DECRYPT_MODE, key, ivParams)

                        try {
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
                    val cis = CipherInputStream(input, cipher)
                    val fos = outputFile.outputStream()
                    try {
                        if (outputFile.exists()) {
                            if (outputFile.absolutePath != DEF_DECRYPTED_FILE_PATH) {
                                erl.onFailure(MSG_OUTPUT_FILE_EXISTS,
                                        FileAlreadyExistsException(outputFile))
                                return@doAsync
                            }
                            outputFile.delete()
                        }
                        outputFile.createNewFile()

                        val iv = ByteArray(cipher.blockSize)
                        val salt = ByteArray(SALT_BYTES_LENGTH)

                        try {
                            if (cipher.blockSize != input.read(iv) ||
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

                        val buffer = ByteArray(8192)
                        var wrote = 0
                        while ({ wrote = cis.read(buffer); wrote }() > 0) {
                            fos.write(buffer)
                            erl.onProgress(wrote)
                        }

                        erl.onSuccess(outputFile as T)

                    } catch (e: IOException) {
                        outputFile.delete()
                        erl.onFailure(MSG_CANNOT_WRITE, e)
                    } finally {
                        fos.flush()
                        fos.close()
                        cis.close()
                    }
                }

                else -> erl.onFailure(MSG_INVALID_INPUT_TYPE, InvalidParameterException())

            }
        }
    }

    fun <T> hash(input: T, algorithm: HashAlgorithms = HashAlgorithms.SHA_512,
                 erl: ECryptResultListener, outputFile: File = File(DEF_HASH_FILE_PATH)) {
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
                    erl.onSuccess(digest.digest(input).asHexString())
                }

                is InputStream -> {

                    val buffer = ByteArray(8192)

                    if (input.available() <= buffer.size) {
                        hash(input.readBytes(), algorithm, erl, outputFile)
                        return@doAsync
                    }

                    try {
                        var read = 0
                        while ({ read = input.read(buffer); read }() > 0) {
                            digest.update(buffer)
                            erl.onProgress(read)
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

                else -> erl.onFailure(MSG_INVALID_INPUT_TYPE, InvalidParameterException())
            }
        }
    }

    interface ECryptResultListener {
        fun onProgress(progressBy: Int) {}
        fun <T> onSuccess(result: T)
        fun onFailure(message: String, e: Exception)
    }

    enum class HashAlgorithms(val value: String) {
        MD5("MD5"),
        SHA_1("SHA-1"),
        SHA_224("SHA-224"),
        SHA_256("SHA-256"),
        SHA_384("SHA-384"),
        SHA_512("SHA-512");
    }

}

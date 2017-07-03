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
import java.io.*
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
    var SECRET_KEY_SPEC_ALGORITHM = "AES"

    private val ECRYPT_FILE_EXT = ".ecrypt"
    private val ENCRYPTED_FILE_NAME = "EncryptedFile"
    private val DECRYPTED_FILE_NAME = "DecryptedFile"
    private val DEF_ENCRYPTED_FILE_PATH =
            Environment.getExternalStorageDirectory().absolutePath +
                    File.separator + ENCRYPTED_FILE_NAME + ECRYPT_FILE_EXT
    private val DEF_DECRYPTED_FILE_PATH =
            Environment.getExternalStorageDirectory().absolutePath +
                    File.separator + DECRYPTED_FILE_NAME + ECRYPT_FILE_EXT

    private val cipher = Cipher.getInstance(TRANSFORMATION)
    private val random = SecureRandom()

    init {
        if (Build.VERSION.SDK_INT >= 26) {
            SECRET_KEY_FAC_ALGORITHM = "PBEwithHmacSHA512AndAES_256"
        }
    }

    @Suppress("UNCHECKED_CAST")
    fun <T> encrypt(input: T, password: String, erl: EncryptionResultListener,
                    outputFile: File = File(DEF_ENCRYPTED_FILE_PATH)) {
        doAsync {

            when (input) {
                is String -> {
                    encrypt(input.asByteArray(), password, erl)
                    return@doAsync
                }
                is CharSequence -> {
                    encrypt(input.toString().asByteArray(), password, erl)
                    return@doAsync
                }
                is File -> {
                    if (!input.exists() || input.isDirectory) {
                        erl.onFailed("File does not exist.", NoSuchFileException(input))
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
                else -> erl.onFailed("Invalid input type.", InvalidParameterException())
            }

            val salt = ByteArray(SALT_BYTES_LENGTH)
            random.nextBytes(salt)

            val keySpec = getKey(password, salt)

            val iv = ByteArray(cipher.blockSize)
            random.nextBytes(iv)
            val ivParams = IvParameterSpec(iv)

            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParams)

            when (input) {

                is ByteArray -> ByteArrayOutputStream().use {

                    it.write(iv)
                    it.write(salt)
                    it.write(cipher.doFinal(input))
                    it.flush()

                    erl.onEncrypted(it.toByteArray().toBase64().asString() as T)
                }

                is FileInputStream -> {
                    val fos = outputFile.outputStream()
                    var cos = CipherOutputStream(fos, cipher)
                    try {
                        if (outputFile.exists()) {
                            if (outputFile.absolutePath != DEF_ENCRYPTED_FILE_PATH) {
                                erl.onFailed("Output file already exists.",
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

                        erl.onEncrypted(outputFile as T)

                    } catch (e: IOException) {
                        outputFile.delete()
                        erl.onFailed("Cannot write to file.", e)
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
    fun <T> decrypt(input: T, password: String, drl: DecryptionResultListener,
                    outputFile: File = File(DEF_DECRYPTED_FILE_PATH)) {
        doAsync {

            when (input) {

                is String -> {
                    decrypt(input.asByteArray(), password, drl)
                    return@doAsync
                }

                is CharSequence -> {
                    decrypt(input.toString().asByteArray(), password, drl)
                    return@doAsync
                }

                is ByteArray -> input.fromBase64().inputStream().use {

                    val IV = ByteArray(cipher.blockSize)
                    if (cipher.blockSize != it.read(IV)) {
                        drl.onFailed("Invalid input data.", BadPaddingException())
                        return@doAsync
                    }
                    val ivParams = IvParameterSpec(IV)

                    val salt = ByteArray(SALT_BYTES_LENGTH)
                    if (SALT_BYTES_LENGTH != it.read(salt)) {
                        drl.onFailed("Invalid input data.", BadPaddingException())
                        return@doAsync
                    }
                    val key = getKey(password, salt)

                    val secureBytes = it.readBytes()
                    cipher.init(Cipher.DECRYPT_MODE, key, ivParams)

                    try {
                        drl.onDecrypted(cipher.doFinal(secureBytes).asString() as T)
                    } catch (e: BadPaddingException) {
                        drl.onFailed("Invalid input data.", e)
                    } catch (e: IllegalBlockSizeException) {
                        drl.onFailed("Invalid input data.", e)
                    }

                }

                is FileInputStream -> {
                    val fos = outputFile.outputStream()
                    val cis = CipherInputStream(input, cipher)
                    try {
                        if (outputFile.exists()) {
                            if (outputFile.absolutePath != DEF_DECRYPTED_FILE_PATH) {
                                drl.onFailed("Output file already exists.",
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
                                drl.onFailed("Invalid input data.", BadPaddingException())
                                return@doAsync
                            }
                        } catch (e: IOException) {
                            drl.onFailed("Cannot read from file.", e)
                            return@doAsync
                        }

                        val key = getKey(password, salt)
                        val ivParams = IvParameterSpec(iv)

                        cipher.init(Cipher.DECRYPT_MODE, key, ivParams)

                        val buffer = ByteArray(8192)
                        var wrote = 0
                        while ({ wrote = cis.read(buffer); wrote }() > 0) {
                            fos.write(buffer)
                            drl.onProgress(wrote)
                        }

                        drl.onDecrypted(outputFile as T)

                    } catch (e: IOException) {
                        outputFile.delete()
                        drl.onFailed("Cannot write to file.", e)
                    } finally {
                        fos.flush()
                        fos.close()
                        cis.close()
                    }
                }

                is File -> {

                    if (!input.exists() || input.isDirectory) {
                        drl.onFailed("File does not exist.", NoSuchFileException(input))
                        return@doAsync
                    }

                    val decryptedFile =
                            if (outputFile.absolutePath == DEF_DECRYPTED_FILE_PATH)
                                File(input.absoluteFile.toString().removeSuffix(ECRYPT_FILE_EXT))
                            else outputFile

                    decrypt(input.inputStream(), password, drl, decryptedFile)
                }

                else -> drl.onFailed("Invalid input type.", InvalidParameterException())

            }
        }
    }

    fun <T> hash(input: T, algorithm: HashAlgorithms = HashAlgorithms.SHA_512,
                 hrl: HashResultListener) {
        doAsync {

            val digest: MessageDigest = MessageDigest.getInstance(algorithm.value)

            when (input) {

                is String -> {
                    hash(input.asByteArray().inputStream(), algorithm, hrl)
                }

                is CharSequence -> {
                    hash(input.toString().asByteArray().inputStream(), algorithm, hrl)
                }

                is File -> {
                    hash(input.inputStream(), algorithm, hrl)
                }

                is ByteArray -> {
                    hrl.onHashed(digest.digest(input).asHexString())
                }

                is InputStream -> {

                    val buffer = ByteArray(8192)

                    if (input.available() <= buffer.size) {
                        hash(input.readBytes(), algorithm, hrl)
                        return@doAsync
                    }

                    try {
                        var read = 0
                        while ({ read = input.read(buffer); read }() > 0) {
                            digest.update(buffer)
                            hrl.onProgress(read)
                        }
                        hrl.onHashed(digest.digest().asHexString())

                    } catch (e: IOException) {
                        hrl.onFailed("Cannot read from file.", e)
                    } finally {
                        input.close()
                    }
                }

                else -> hrl.onFailed("Invalid input type.", InvalidParameterException())
            }
        }
    }

    interface EncryptionResultListener {
        fun onProgress(progressBy: Int) {}
        fun <T> onEncrypted(result: T)
        fun onFailed(message: String, e: Exception)
    }

    interface DecryptionResultListener {
        fun onProgress(progressBy: Int) {}
        fun <T> onDecrypted(result: T)
        fun onFailed(message: String, e: Exception)
    }

    interface HashResultListener {
        fun onProgress(progressBy: Int) {}
        fun <T> onHashed(result: T)
        fun onFailed(message: String, e: Exception)
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

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

import com.pvryan.easycrypt.Constants
import com.pvryan.easycrypt.ECResultListener
import com.pvryan.easycrypt.extensions.generateRandom
import com.pvryan.easycrypt.extensions.handleSuccess
import kotlinx.coroutines.experimental.CoroutineStart
import kotlinx.coroutines.experimental.Dispatchers
import kotlinx.coroutines.experimental.GlobalScope
import kotlinx.coroutines.experimental.launch
import timber.log.Timber
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileInputStream
import java.io.IOException
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

@PublishedApi
internal inline fun <reified T> encryptSymmetric(
        input: Any,
        password: String,
        cipher: Cipher,
        erl: ECResultListener<T>,
        outputFile: File
) = GlobalScope.launch(Dispatchers.Default, CoroutineStart.DEFAULT, null) {

    val salt = ByteArray(Constants.SALT_BYTES_LENGTH).generateRandom()

    val keySpec = getKey(password, salt)

    val iv = ByteArray(cipher.blockSize).generateRandom()
    val ivParams = IvParameterSpec(iv)

    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParams)

    when (input) {

        is ByteArray -> (iv.plus(salt).plus(cipher.doFinal(input))).handleSuccess(erl, outputFile, true)

        is FileInputStream -> {

            val fos = with(outputFile) {
                if (exists()) delete()
                createNewFile()
                outputStream()
            }

            try {
                fos.write(iv)
                fos.write(salt)
            } catch (e: IOException) {
                Timber.d(e)
                fos.flush()
                fos.close()
                input.close()
                outputFile.delete()
                erl.onFailure?.invoke(Constants.ERR_CANNOT_WRITE, e)
                return@launch
            }

            CipherOutputStream(fos, cipher).run {
                try {
                    val size = input.channel.size()
                    val buffer = ByteArray(8192)
                    var bytesCopied: Long = 0
                    var read = input.read(buffer)

                    while (read > -1) {
                        write(buffer, 0, read)
                        bytesCopied += read
                        erl.onProgress?.invoke(read, bytesCopied, size)
                        read = input.read(buffer)
                    }

                } catch (e: IOException) {
                    Timber.d(e)
                    outputFile.delete()
                    erl.onFailure?.invoke(Constants.ERR_CANNOT_WRITE, e)
                    return@launch
                } finally {
                    flush()
                    close()
                    input.close()
                }
            }
            erl.onSuccess?.invoke(outputFile as T)
        }
    }
}

@PublishedApi
internal inline fun <reified T> decryptSymmetric(
        input: Any,
        password: String,
        cipher: Cipher,
        erl: ECResultListener<T>,
        outputFile: File
) = GlobalScope.launch(Dispatchers.Default, CoroutineStart.DEFAULT, null) {

    val ivBytesLength = cipher.blockSize

    when (input) {

        is ByteArrayInputStream -> {

            val iv = ByteArray(ivBytesLength)
            val salt = ByteArray(Constants.SALT_BYTES_LENGTH)

            if (ivBytesLength != input.read(iv) || Constants.SALT_BYTES_LENGTH != input.read(salt)) {
                input.close()
                erl.onFailure?.invoke(Constants.ERR_INVALID_INPUT_DATA, BadPaddingException())
                return@launch
            }

            val ivParams = IvParameterSpec(iv)
            val key = getKey(password, salt)

            try {
                cipher.init(Cipher.DECRYPT_MODE, key, ivParams)

                val secureBytes = input.readBytes()
                cipher.doFinal(secureBytes).handleSuccess(erl, outputFile, false)

            } catch (e: BadPaddingException) {
                Timber.d(e)
                erl.onFailure?.invoke(Constants.ERR_INVALID_INPUT_DATA, e)
            } catch (e: IllegalBlockSizeException) {
                Timber.d(e)
                erl.onFailure?.invoke(Constants.ERR_INVALID_INPUT_DATA, e)
            } finally {
                input.close()
            }
        }

        is FileInputStream -> {

            var cis: CipherInputStream? = null

            val fos = with(outputFile) {
                if (exists()) delete()
                createNewFile()
                outputStream()
            }

            val iv = ByteArray(ivBytesLength)
            val salt = ByteArray(Constants.SALT_BYTES_LENGTH)

            try {
                if (ivBytesLength != input.read(iv) ||
                        Constants.SALT_BYTES_LENGTH != input.read(salt)) {
                    input.close()
                    erl.onFailure?.invoke(Constants.ERR_INVALID_INPUT_DATA, BadPaddingException())
                    return@launch
                }
            } catch (e: IOException) {
                Timber.d(e)
                input.close()
                erl.onFailure?.invoke(Constants.ERR_CANNOT_READ, e)
                return@launch
            }

            val key = getKey(password, salt)
            val ivParams = IvParameterSpec(iv)

            cipher.init(Cipher.DECRYPT_MODE, key, ivParams)

            try {
                val size = input.channel.size()
                cis = CipherInputStream(input, cipher)

                val buffer = ByteArray(8192)
                var bytesCopied: Long = 0

                var read = cis.read(buffer)
                while (read > -1) {
                    fos.write(buffer, 0, read)
                    bytesCopied += read
                    erl.onProgress?.invoke(read, bytesCopied, size)
                    read = cis.read(buffer)
                }

            } catch (e: IOException) {
                Timber.d(e)
                outputFile.delete()
                erl.onFailure?.invoke(Constants.ERR_CANNOT_WRITE, e)
                return@launch
            } finally {
                fos.flush()
                fos.close()
                cis?.close()
            }
            erl.onSuccess?.invoke(outputFile as T)
        }
    }
}

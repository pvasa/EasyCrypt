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
package com.pvryan.easycrypt

import com.pvryan.easycrypt.asymmetric.ECAsymmetric.KeySizes
import com.pvryan.easycrypt.asymmetric.ECRSAKeyPairListener
import com.pvryan.easycrypt.extensions.fromBase64
import com.pvryan.easycrypt.randomorg.RandomOrg
import com.pvryan.easycrypt.randomorg.RandomOrgResponse
import com.pvryan.easycrypt.symmetric.ECPasswordListener
import org.jetbrains.anko.doAsync
import org.jetbrains.annotations.NotNull
import retrofit2.Call
import retrofit2.Callback
import retrofit2.Response
import java.net.HttpURLConnection
import java.security.InvalidParameterException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

@Suppress("unused")
class ECKeys {

    /**
     * Generate pseudo-random password using Java's [SecureRandom] number generator.
     *
     * @param length of password to be generated (range 1 to 4096)
     * @param symbols (optional) to be used in the password
     *
     * @return [String] password of specified [length]
     *
     * @throws InvalidParameterException when length is less than 1
     */
    @Throws(InvalidParameterException::class)
    @JvmOverloads
    fun genSecureRandomPassword(@NotNull length: Int,
                                @NotNull symbols: CharArray =
                                Constants.STANDARD_SYMBOLS.toCharArray()): String {

        if (length < 1 || length > 4096) throw InvalidParameterException(
                "Invalid length. Valid range is 1 to 4096.")

        if (symbols.isEmpty()) throw InvalidParameterException(
                "Array of symbols cannot be empty.")

        val password = CharArray(length)
        for (i in 0 until length) {
            password[i] = symbols[Constants.random.nextInt(symbols.size - 1)]
        }
        return password.joinToString("")
    }

    /**
     * Generate true random password using random.org service
     * and posts response to [ECPasswordListener.onGenerated] if successful or
     * posts error to [ECPasswordListener.onFailure] if failed.
     * Result is a [String] password of specified [length].
     *
     * @param length of password to be generated (range 1 to 4096)
     * @param randomOrgApiKey provided by api.random.org/api-keys/beta
     * @param resultListener listener interface of type [ECPasswordListener]
     * where generated password will be posted
     */
    fun genRandomOrgPassword(@NotNull length: Int, @NotNull randomOrgApiKey: String,
                             @NotNull resultListener: ECPasswordListener) {

        if (length < 1 || length > 4096) {
            resultListener.onFailure(
                    "Invalid length.",
                    InvalidParameterException("Valid range is 1 to 4096."))
            return
        }

        var oddLength = false

        val passLength =
                if (length.rem(2) != 0) {
                    oddLength = true
                    length + 1
                } else length

        RandomOrg.request(randomOrgApiKey, passLength, object : Callback<RandomOrgResponse> {

            override fun onResponse(call: Call<RandomOrgResponse>,
                                    response: Response<RandomOrgResponse>) {

                if (HttpURLConnection.HTTP_OK == response.code()) {

                    val body = response.body()

                    if (body != null) {

                        if (body.error != null) {
                            resultListener.onFailure("Error response from random.org",
                                    InvalidParameterException(body.error.message))
                            return
                        }

                        val randomKeyArray = body.result.random.data
                        val randomKeyHex = StringBuilder()
                        for (i in 0..(randomKeyArray.size() - 1)) {
                            randomKeyHex.append(randomKeyArray[i].toString()
                                    .replace("\"", "", true))
                        }

                        if (oddLength)
                            resultListener.onGenerated(randomKeyHex.toString().dropLast(1))
                        else resultListener.onGenerated(randomKeyHex.toString())

                    } else {
                        resultListener.onFailure("Random.org error.",
                                Exception(response.errorBody()?.string()
                                        ?: "Null response from Random.org. Please try again."))
                    }
                } else {
                    resultListener.onFailure("Response code ${response.code()}",
                            Exception(response.errorBody()?.string()
                                    ?: "Some error occurred at Random.org. Please try again."))
                }
            }

            override fun onFailure(call: Call<RandomOrgResponse>, t: Throwable) {
                resultListener.onFailure(t.localizedMessage, Exception(t))
            }
        })
    }

    /**
     * Generate a key pair with keys of specified length (default 4096) for RSA algorithm.
     *
     * @param kpl listener interface of type [ECRSAKeyPairListener]
     * where generated keypair will be posted
     * @param keySize of type [KeySizes] which can be 2048 or 4096 (default)
     */
    @JvmOverloads
    fun genRSAKeyPair(kpl: ECRSAKeyPairListener,
                      keySize: KeySizes = KeySizes.S_4096) {
        doAsync {
            val generator = KeyPairGenerator.getInstance(Constants.ASYMMETRIC_ALGORITHM)
            generator.initialize(keySize.value, Constants.random)
            val keyPair = generator.generateKeyPair()
            kpl.onGenerated(keyPair)
        }
    }

    /**
     * Retrieve [RSAPublicKey] from base64 encoded string.
     *
     * @param keyBase64String base64 encoded public key string (X.509 format)
     *
     * @return [RSAPublicKey]
     *
     * @throws IllegalArgumentException when [keyBase64String] is not a valid base64 string
     * @throws InvalidKeySpecException when input is not a valid key
     */
    @Throws(IllegalArgumentException::class, InvalidKeySpecException::class)
    fun genRSAPublicKeyFromBase64(keyBase64String: String) =
            KeyFactory.getInstance(Constants.ASYMMETRIC_ALGORITHM)
                    .generatePublic(X509EncodedKeySpec(keyBase64String.fromBase64())) as RSAPublicKey

    /**
     * Retrieve [RSAPrivateKey] from base64 encoded string.
     *
     * @param keyBase64String base64 encoded private key string (PKCS#8 format)
     *
     * @return [RSAPrivateKey]
     *
     * @throws IllegalArgumentException when [keyBase64String] is not a valid base64 string
     * @throws InvalidKeySpecException when input is not a valid key
     */
    @Throws(IllegalArgumentException::class, InvalidKeySpecException::class)
    fun genRSAPrivateKeyFromBase64(keyBase64String: String) =
            KeyFactory.getInstance(Constants.ASYMMETRIC_ALGORITHM)
                    .generatePrivate(PKCS8EncodedKeySpec(keyBase64String.fromBase64())) as RSAPrivateKey
}

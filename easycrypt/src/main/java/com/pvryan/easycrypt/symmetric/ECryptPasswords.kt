package com.pvryan.easycrypt.symmetric

import com.pvryan.easycrypt.Constants
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
import java.net.HttpURLConnection
import java.security.InvalidParameterException
import java.security.SecureRandom

class ECryptPasswords {

    /**
     * Generate pseudo-random password using Java's [SecureRandom] number generator.
     *
     * @param length of password to be generated
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

        val password = CharArray(length)
        for (i in 0..length - 1) {
            password[i] = symbols[Constants.random.nextInt(symbols.size - 1)]
        }
        return password.joinToString("")
    }

    /**
     * Generate true random password using random.org service
     * and posts response to [ECryptPasswordListener.onSuccess] if successful or
     * posts error to [ECryptPasswordListener.onFailure] if failed.
     * Result is a [String] password of specified [length].
     *
     * @param length of password to be generated (range 1 to 4096)
     * @param randomOrgApiKey provided by api.random.org/api-keys/beta
     * @param resultListener listener interface of type [ECryptPasswordListener] where generated password will be posted
     */
    fun genRandomOrgPassword(@NotNull length: Int, @NotNull randomOrgApiKey: String,
                             @NotNull resultListener: ECryptPasswordListener) {

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
                } else {
                    length
                }

        doAsync {

            val retrofit = Retrofit.Builder().baseUrl(RandomOrgApis.BASE_URL)
                    .addConverterFactory(GsonConverterFactory.create()).build()

            val randomOrgApis: RandomOrgApis = retrofit.create(RandomOrgApis::class.java)

            val params = RandomOrgRequest.Params(apiKey = randomOrgApiKey, n = passLength / 2)
            val postData = RandomOrgRequest(params = params)

            randomOrgApis.request(postData).enqueue(object : Callback<RandomOrgResponse> {

                override fun onFailure(call: Call<RandomOrgResponse>, t: Throwable) {
                    resultListener.onFailure(t.localizedMessage, Exception(t))
                }

                override fun onResponse(call: Call<RandomOrgResponse>, response: Response<RandomOrgResponse>) {

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
                                randomKeyHex.append(randomKeyArray[i].toString().replace("\"", "", true))
                            }

                            if (oddLength)
                                resultListener.onSuccess(randomKeyHex.toString().dropLast(1))
                            else resultListener.onSuccess(randomKeyHex.toString())

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
}
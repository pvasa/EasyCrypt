package com.pvryan.easycrypt.randomorg

import retrofit2.Call
import retrofit2.http.Body
import retrofit2.http.POST

/**
 * Interface for Retrofit api calls
 */
interface RandomOrgApis {

    @POST("json-rpc/1/invoke")
    fun request(@Body body: RandomOrgRequest): Call<RandomOrgResponse>

    companion object {
        val BASE_URL = "https://api.random.org/"
        val RESULT_OBJECT = "result"
        val RANDOM_OBJECT = "random"
        val DATA_ARRAY = "data"
    }
}

package com.pvryan.easycrypt.randomorg

import retrofit2.Callback
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory

internal class RandomOrg {

    companion object {

        internal fun request(apiKey: String, passLength: Int, callback: Callback<RandomOrgResponse>) {

            val retrofit = Retrofit.Builder().baseUrl(RandomOrgApis.BASE_URL)
                    .addConverterFactory(GsonConverterFactory.create()).build()

            val randomOrgApis: RandomOrgApis = retrofit.create(RandomOrgApis::class.java)

            val params = RandomOrgRequest.Params(apiKey = apiKey, n = passLength / 2)
            val post = RandomOrgRequest(params = params)

            randomOrgApis.request(post).enqueue(callback)
        }
    }
}

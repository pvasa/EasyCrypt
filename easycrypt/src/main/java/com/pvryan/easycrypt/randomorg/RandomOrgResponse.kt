package com.pvryan.easycrypt.randomorg

import com.google.gson.JsonArray

data class RandomOrgResponse(
        val jsonrpc: String,
        val error: Error,
        val result: Result,
        val id: Int
) {
    data class Error(
            val code: Int,
            val message: String
    )

    data class Result(
            val random: Random,
            val bitsUsed: Long,
            val bitsLeft: Long,
            val requestsLeft: Int
    ) {
        data class Random(
                val data: JsonArray
        )
    }
}

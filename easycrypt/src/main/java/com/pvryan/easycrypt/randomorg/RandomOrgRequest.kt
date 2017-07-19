package com.pvryan.easycrypt.randomorg

data class RandomOrgRequest(
        val jsonrpc: String = "2.0",
        val method: String = "generateIntegers",
        val params: Params = RandomOrgRequest.Params()
        ,
        val id: Int = 679
) {
    data class Params(
            val apiKey: String = "43e7bf3d-1e81-4dcd-b335-1d9efc1661db",
            val n: Int = 32,
            val min: Int = 0,
            val max: Int = 255,
            val replacement: Boolean = false,
            val base: Int = 16
    )
}

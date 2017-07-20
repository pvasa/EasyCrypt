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

package com.pvryan.easycrypt.randomorg

/**
 * Request structure for api.random.org
 */
data class RandomOrgRequest(
        val jsonrpc: String = "2.0",
        val method: String = "generateIntegers",
        val params: Params = RandomOrgRequest.Params(),
        val id: Int = 679
) {
    data class Params(
            val apiKey: String = "",
            val n: Int = 32,
            val min: Int = 0,
            val max: Int = 255,
            val replacement: Boolean = false,
            val base: Int = 16
    )
}

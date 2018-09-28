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

import kotlinx.coroutines.experimental.Dispatchers
import kotlinx.coroutines.experimental.GlobalScope
import kotlinx.coroutines.experimental.android.Main
import kotlinx.coroutines.experimental.launch

/**
 * Interface to listen for result from encryption, decryption, or hashing
 */
class ECResultListener<T> {

    /**
     * @param newBytes count processed after last block
     * @param bytesProcessed count from total input
     */
    @PublishedApi
    internal var onProgress: ((newBytes: Int, bytesProcessed: Long, totalBytes: Long) -> Unit)? = null

    /**
     * @param result on successful execution of the calling method
     */
    @PublishedApi
    internal var onSuccess: ((result: T) -> Unit)? = null

    /**
     * @param message on failure
     * @param e exception thrown by called method
     */
    @PublishedApi
    internal var onFailure: ((message: String, e: Throwable) -> Unit)? = null

    inline fun onSuccess(crossinline run: (result: T) -> Unit): ECResultListener<T> {
        onSuccess = { GlobalScope.launch(Dispatchers.Main) { run(it) } }
        return this
    }

    inline fun onFailure(crossinline run: (message: String, e: Throwable) -> Unit): ECResultListener<T> {
        onFailure = { message: String, e: Throwable -> GlobalScope.launch(Dispatchers.Main) { run(message, e) } }
        return this
    }

    inline fun onProgress(crossinline run: (newBytes: Int, bytesProcessed: Long, totalBytes: Long) -> Unit): ECResultListener<T> {
        onProgress = { newBytes, bytesProcessed, totalBytes ->
            GlobalScope.launch(Dispatchers.Main) { run(newBytes, bytesProcessed, totalBytes) }
        }
        return this
    }
}

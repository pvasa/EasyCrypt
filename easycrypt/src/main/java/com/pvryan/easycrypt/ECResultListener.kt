package com.pvryan.easycrypt

/**
 * Interface to listen for result from encryption, decryption, or hashing
 */
interface ECResultListener {
    /**
     * @param newBytes count processed after last block
     * @param bytesProcessed count from total input
     */
    fun onProgress(newBytes: Int, bytesProcessed: Long) {}

    /**
     * @param result on successful execution of the calling method
     */
    fun <T> onSuccess(result: T)

    /**
     * @param message on failure
     * @param e exception thrown by called method
     */
    fun onFailure(message: String, e: Exception)
}
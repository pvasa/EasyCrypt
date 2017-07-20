package com.pvryan.easycrypt

/**
 * Transformations that can be used for encryption/decryption
 */
enum class ECryptTransformations(val value: String) {

    AES_CTR_NoPadding("AES/CTR/NoPadding"),
    AES_CBC_PKCS7Padding("AES/CBC/PKCS7Padding")

}

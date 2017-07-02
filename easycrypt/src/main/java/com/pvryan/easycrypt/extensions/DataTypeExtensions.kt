package com.pvryan.easycrypt.extensions

import android.util.Base64

private val HEX_CHARS = "0123456789ABCDEF".toCharArray()
fun ByteArray.asString(): String = this.toString(Charsets.UTF_8)
fun ByteArray.toBase64(): ByteArray = Base64.encode(this, Base64.DEFAULT)
fun ByteArray.fromBase64(): ByteArray = Base64.decode(this, Base64.DEFAULT)
fun ByteArray.toHexString(): String {
    val result = StringBuffer()
    forEach {
        val octet = it.toInt()
        val firstIndex = (octet and 0xF0).ushr(4)
        val secondIndex = octet and 0x0F
        result.append(HEX_CHARS[firstIndex])
        result.append(HEX_CHARS[secondIndex])
    }
    return result.toString()
}

fun String.asByteArray(): ByteArray = this.toByteArray(Charsets.UTF_8)
fun String.toBase64(): String = this.asByteArray().toBase64().asString()
fun String.fromBase64(): String = this.asByteArray().fromBase64().asString()

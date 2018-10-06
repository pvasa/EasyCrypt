package com.pvryan.easycrypt

import com.pvryan.easycrypt.extensions.asByteArray
import com.pvryan.easycrypt.extensions.fromBase64
import com.pvryan.easycrypt.symmetric.isDefault
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileInputStream
import java.io.InputStream

@Throws(IllegalArgumentException::class,
        NoSuchFileException::class,
        FileAlreadyExistsException::class)
internal fun Pair<Any, File>.parse(forEncrypt: Boolean): Triple<Any, File, Long> {

    val input: Any = first
    val outputFile: File = second

    var inputSize = Long.MAX_VALUE

    val parsedInput = when (input) {
        is ByteArrayInputStream -> {
            inputSize = input.available().toLong()
            input.readBytes(input.available())
        }
        is FileInputStream -> {
            inputSize = input.channel.size()
            input
        }
        is File -> {
            inputSize = input.length()
            input.inputStream()
        }
        is ByteArray -> {
            inputSize = input.size.toLong()
            input
        }
        is String -> {
            (if (forEncrypt) input.asByteArray() else input.fromBase64()).also {
                inputSize = it.size.toLong()
            }
        }
        is CharSequence ->
            (if (forEncrypt) input.toString().asByteArray() else input.toString().fromBase64()).also {
                inputSize = it.size.toLong()
            }
        else -> throw IllegalArgumentException(Constants.ERR_INPUT_TYPE_NOT_SUPPORTED)
    }

    val parsedOutputFile = if (input is File) {
        if (!input.exists() || input.isDirectory) {
            throw NoSuchFileException(input, reason = Constants.ERR_NO_SUCH_FILE)
        }
        if (!outputFile.isDefault()) {
            if (outputFile.exists()) {
                (parsedInput as? InputStream)?.close()
                throw FileAlreadyExistsException(outputFile, reason = Constants.ERR_OUTPUT_FILE_EXISTS)
            }
            outputFile
        } else File(input.absolutePath + Constants.ECRYPT_FILE_EXT)
    } else outputFile

    return Triple(parsedInput, parsedOutputFile, inputSize)
}

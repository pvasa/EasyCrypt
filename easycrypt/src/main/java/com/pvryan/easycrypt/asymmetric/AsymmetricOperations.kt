package com.pvryan.easycrypt.asymmetric

import com.pvryan.easycrypt.Constants
import com.pvryan.easycrypt.ECResultListener
import com.pvryan.easycrypt.extensions.asString
import com.pvryan.easycrypt.extensions.fromBase64
import com.pvryan.easycrypt.extensions.toBase64
import kotlinx.coroutines.experimental.CoroutineStart
import kotlinx.coroutines.experimental.Dispatchers
import kotlinx.coroutines.experimental.GlobalScope
import kotlinx.coroutines.experimental.launch
import timber.log.Timber
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStream
import java.security.InvalidParameterException
import java.security.Signature
import java.security.SignatureException
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

private val signature = Signature.getInstance(Constants.SIGNATURE_ALGORITHM)

@PublishedApi
internal fun asymmetricSign(
        input: Any,
        privateKey: RSAPrivateKey,
        erl: ECResultListener<File>,
        outputFile: File
) = GlobalScope.launch(Dispatchers.Default, CoroutineStart.DEFAULT, null) {

    if (outputFile.exists()) {
        (input as? InputStream)?.close()
        erl.onFailure?.invoke(Constants.ERR_OUTPUT_FILE_EXISTS, FileAlreadyExistsException(outputFile))
        return@launch
    }

    signature.initSign(privateKey)

    when (input) {

        is InputStream -> {

            val buffer = ByteArray(8192)
            var bytesCopied: Long = 0

            try {
                val size = (input as? FileInputStream)?.channel?.size() ?: -1
                var read = input.read(buffer)

                while (read > -1) {
                    signature.update(buffer, 0, read)
                    bytesCopied += read
                    erl.onProgress?.invoke(read, bytesCopied, size)
                    read = input.read(buffer)
                }

                try {
                    outputFile.outputStream().use {
                        it.write(signature.sign().toBase64())
                        it.flush()
                    }
                    erl.onSuccess?.invoke(outputFile)
                } catch (e: IOException) {
                    Timber.d(e)
                    erl.onFailure?.invoke(Constants.ERR_CANNOT_WRITE, e)
                }

            } catch (e: IOException) {
                Timber.d(e)
                outputFile.delete()
                erl.onFailure?.invoke(Constants.ERR_CANNOT_WRITE, e)
            } catch (e: SignatureException) {
                Timber.d(e)
                outputFile.delete()
                erl.onFailure?.invoke(Constants.ERR_SIGN_EXCEPTION, e)
            }
        }
    }
}

internal fun asymmetricVerify(
        input: Any,
        publicKey: RSAPublicKey,
        sigFile: File,
        erl: ECResultListener<Boolean>
) = GlobalScope.launch(Dispatchers.Default, CoroutineStart.DEFAULT, null) {

    signature.initVerify(publicKey)

    if (input is InputStream) {

        val buffer = ByteArray(8192)
        var bytesCopied: Long = 0

        try {
            val size = (input as? FileInputStream)?.channel?.size() ?: -1
            var read = input.read(buffer)

            while (read > -1) {
                signature.update(buffer, 0, read)
                bytesCopied += read
                erl.onProgress?.invoke(read, bytesCopied, size)
                read = input.read(buffer)
            }

            try {
                erl.onSuccess?.invoke(signature.verify(sigFile.readBytes().asString().fromBase64()))
            } catch (e: IllegalArgumentException) {
                Timber.d(e)
                erl.onFailure?.invoke(Constants.ERR_BAD_BASE64, e)
            } catch (e: SignatureException) {
                Timber.d(e)
                erl.onFailure?.invoke(Constants.ERR_VERIFY_EXCEPTION, e)
            }

        } catch (e: IOException) {
            Timber.d(e)
            erl.onFailure?.invoke(Constants.ERR_CANNOT_WRITE, e)
        }
    } else erl.onFailure?.invoke(Constants.ERR_INPUT_TYPE_NOT_SUPPORTED, InvalidParameterException())
}

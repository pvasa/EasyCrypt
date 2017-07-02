package com.pvryan.easycrypt

import android.os.Build
import com.pvryan.easycrypt.extensions.*
import org.jetbrains.anko.AnkoLogger
import org.jetbrains.anko.doAsync
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.spec.KeySpec
import javax.crypto.*
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class ECrypt : AnkoLogger {

    private val KEY_BITS_LENGTH = 256
    private val SALT_BYTES_LENGTH = KEY_BITS_LENGTH / 8

    private val ITERATIONS = 10000 //ideally 10000

    private val TRANSFORMATION = "AES/CBC/PKCS5Padding"
    private var SECRET_KEY_FAC_ALGORITHM = "PBKDF2WithHmacSHA1"
    private var SECRET_KEY_SPEC_ALGORITHM = "AES"

    private val FILE_EXT = ".ecrypt"

    private val cipher = Cipher.getInstance(TRANSFORMATION)
    private val random = SecureRandom()

    init {
        if (Build.VERSION.SDK_INT >= 26) {
            SECRET_KEY_FAC_ALGORITHM = "PBEwithHmacSHA512AndAES_256"
        }
    }

    private fun getKey(password: String = String(), salt: ByteArray): SecretKeySpec {

        var pass = password

        if (password.isNullOrBlank()) {
            val passBytes = ByteArray(32)
            random.nextBytes(passBytes)
            pass = passBytes.asString()
        }

        val pbeKeySpec: KeySpec = PBEKeySpec(pass.toCharArray(), salt, ITERATIONS, KEY_BITS_LENGTH)

        val keyFactory: SecretKeyFactory =
                SecretKeyFactory.getInstance(SECRET_KEY_FAC_ALGORITHM)

        val keyBytes = keyFactory.generateSecret(pbeKeySpec).encoded
        val keySpec = SecretKeySpec(keyBytes, SECRET_KEY_SPEC_ALGORITHM)

        return keySpec
    }

    @Suppress("UNCHECKED_CAST")
    fun <T> encrypt(input: T, erl: EncryptionResultListener, password: String) {
        doAsync {

            when (input) {
                is String -> {
                    encrypt(input.asByteArray(), erl, password)
                    return@doAsync
                }
                is CharSequence -> {
                    encrypt(input.toString().asByteArray(), erl, password)
                    return@doAsync
                }
                is File -> {
                    if (!input.exists()) {
                        erl.onFailed("File does not exist.")
                        return@doAsync
                    } else if (input.isDirectory) {
                        erl.onFailed("Cannot encrypt folder.")
                        return@doAsync
                    }
                }
                is ByteArray -> {
                }
                else -> erl.onFailed("Invalid input type.")
            }

            val salt = ByteArray(SALT_BYTES_LENGTH)
            random.nextBytes(salt)

            val keySpec = getKey(password, salt)

            val iv = ByteArray(cipher.blockSize)
            random.nextBytes(iv)
            val ivParams = IvParameterSpec(iv)

            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParams)

            when (input) {

                is ByteArray -> ByteArrayOutputStream().use {

                    it.write(iv)
                    it.write(salt)
                    it.write(cipher.doFinal(input))
                    it.flush()

                    erl.onEncrypted(it.toByteArray().toBase64().asString() as T)
                }

                is File -> {
                    val fis = input.inputStream()

                    val encryptedFile = File(input.absolutePath + FILE_EXT)
                    val fos = encryptedFile.outputStream()
                    fos.write(iv)
                    fos.write(salt)
                    val cos = CipherOutputStream(fos, cipher)

                    fis.copyTo(cos)
                    cos.flush()
                    cos.close()
                    fis.close()

                    input.delete()

                    erl.onEncrypted(encryptedFile as T)
                }
            }
        }
    }

    @Suppress("UNCHECKED_CAST")
    fun <T> decrypt(input: T, drl: DecryptionResultListener, password: String) {
        doAsync {

            when (input) {

                is String -> {
                    decrypt(input.asByteArray(), drl, password)
                    return@doAsync
                }

                is CharSequence -> {
                    decrypt(input.toString(), drl, password)
                    return@doAsync
                }

                is ByteArray -> input.fromBase64().inputStream().use {

                    val IV = ByteArray(cipher.blockSize)
                    if (cipher.blockSize != it.read(IV)) {
                        drl.onFailed("Invalid input data.")
                        return@doAsync
                    }
                    val ivParams = IvParameterSpec(IV)

                    val salt = ByteArray(SALT_BYTES_LENGTH)
                    if (SALT_BYTES_LENGTH != it.read(salt)) {
                        drl.onFailed("Invalid input data.")
                        return@doAsync
                    }
                    val key = getKey(password, salt)

                    val secureBytes = it.readBytes()
                    cipher.init(Cipher.DECRYPT_MODE, key, ivParams)

                    try {
                        drl.onDecrypted(cipher.doFinal(secureBytes).asString() as T)
                    } catch (e: BadPaddingException) {
                        drl.onFailed("Invalid input data.")
                    } catch (e: IllegalBlockSizeException) {
                        drl.onFailed("Invalid input data.")
                    }

                }

                is File -> {

                    if (!input.exists()) {
                        drl.onFailed("File does not exist.")
                        return@doAsync
                    } else if (input.isDirectory) {
                        drl.onFailed("Cannot decrypt folder.")
                        return@doAsync
                    }

                    val fis = input.inputStream()
                    val decryptedFile = File(input.absoluteFile.toString().removeSuffix(FILE_EXT))
                    val fos = decryptedFile.outputStream()

                    val iv = ByteArray(cipher.blockSize)
                    val salt = ByteArray(SALT_BYTES_LENGTH)
                    if (cipher.blockSize != fis.read(iv) || SALT_BYTES_LENGTH != fis.read(salt)) {
                        drl.onFailed("Invalid input data.")
                        return@doAsync
                    }
                    val key = getKey(password, salt)
                    val ivParams = IvParameterSpec(iv)

                    cipher.init(Cipher.DECRYPT_MODE, key, ivParams)
                    val cis = CipherInputStream(fis, cipher)

                    cis.copyTo(fos)
                    fos.flush()
                    fos.close()
                    cis.close()

                    drl.onDecrypted(decryptedFile as T)
                }

                else -> drl.onFailed("Invalid input type.")

            }
        }
    }

    fun <T> hash(input: T, hrl: HashResultListener,
                 algorithm: HashAlgorithms = HashAlgorithms.SHA_512) {
        doAsync {

            val digest: MessageDigest = MessageDigest.getInstance(algorithm.value)

            when (input) {

                is String -> {
                    hash(input.asByteArray(), hrl, algorithm)
                    return@doAsync
                }

                is CharSequence -> {
                    hash(input.toString().asByteArray(), hrl, algorithm)
                    return@doAsync
                }

                is ByteArray -> {
                    hrl.onHashed(digest.digest(input).toHexString())
                }

                else -> hrl.onFailed("Invalid input type.")
            }
        }
    }

    interface EncryptionResultListener {
        fun <T> onEncrypted(result: T)
        fun onFailed(error: String)
    }

    interface DecryptionResultListener {
        fun <T> onDecrypted(result: T)
        fun onFailed(error: String)
    }

    interface HashResultListener {
        fun <T> onHashed(result: T)
        fun onFailed(error: String)
    }

    enum class HashAlgorithms(val value: String) {
        MD5("MD5"),
        SHA_1("SHA-1"),
        SHA_224("SHA-224"),
        SHA_256("SHA-256"),
        SHA_384("SHA-384"),
        SHA_512("SHA-512");
    }

}

/*
@Suppress("unused")
object Transformations {
    val AES_CBC_NoPadding = "AES/CBC/NoPadding" //(128)
    val AES_CBC_PKCS5Padding = "AES/CBC/PKCS5Padding" //(128)
    val AES_ECB_NoPadding = "AES/ECB/NoPadding" //(128)
    val AES_ECB_PKCS5Padding = "AES/ECB/PKCS5Padding" //(128)
    val DES_CBC_NoPadding = "DES/CBC/NoPadding" //(56)
    val DES_CBC_PKCS5Padding = "DES/CBC/PKCS5Padding" //(56)
    val DES_ECB_NoPadding = "DES/ECB/NoPadding" //(56)
    val DES_ECB_PKCS5Padding = "DES/ECB/PKCS5Padding" //(56)
    val DESede_CBC_NoPadding = "DESede/CBC/NoPadding" //(168)
    val DESede_CBC_PKCS5Padding = "DESede/CBC/PKCS5Padding" //(168)
    val DESede_ECB_NoPadding = "DESede/ECB/NoPadding" //(168)
    val DESede_ECB_PKCS5Padding = "DESede/ECB/PKCS5Padding" //(168)
    val RSA_ECB_PKCS1Padding = "RSA/ECB/PKCS1Padding" //(1024, 2048)
    val RSA_ECB_OAEPWithSHA_1AndMGF1Padding = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding" //(1024, 2048)
    val RSA_ECB_OAEPWithSHA_256AndMGF1Padding = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding" //(1024, 2048)
}
when(transformation) {
    with(Transformations) {
        AES_CBC_NoPadding
        AES_CBC_PKCS5Padding
        AES_ECB_NoPadding
        AES_ECB_PKCS5Padding
    } -> {
        SECRET_KEY_SPEC_ALGORITHM = "AES"
    }
    with(Transformations) {
        DES_CBC_NoPadding
        DES_CBC_PKCS5Padding
        DES_ECB_NoPadding
        DES_ECB_PKCS5Padding
    } -> {
        SECRET_KEY_SPEC_ALGORITHM = "DES"
    }
    with(Transformations) {
        DESede_CBC_NoPadding
        DESede_CBC_PKCS5Padding
        DESede_ECB_NoPadding
        DESede_ECB_PKCS5Padding
    } -> {
        SECRET_KEY_SPEC_ALGORITHM = "DESede"
    }
    with(Transformations) {
        RSA_ECB_PKCS1Padding
        RSA_ECB_OAEPWithSHA_1AndMGF1Padding
        RSA_ECB_OAEPWithSHA_256AndMGF1Padding
    } -> {
        SECRET_KEY_SPEC_ALGORITHM = "RSA"
    }
}
*/

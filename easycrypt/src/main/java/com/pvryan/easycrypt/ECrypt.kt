package com.pvryan.easycrypt

import android.os.Build
import android.util.Base64
import java.nio.charset.Charset
import java.security.SecureRandom
import java.security.spec.KeySpec
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class ECrypt(transformation: String = ECrypt.Transformations.AES_CBC_PKCS5Padding) {

    private val CHARSET = Charset.forName("UTF-8")

    private val cipher = Cipher.getInstance(transformation)

    private val KEY_SIZE_BITS = 256

    private val SALT_SIZE_BYTES = KEY_SIZE_BITS / 8

    private val iterations = 10000

    private val random = SecureRandom()

    private var SECRET_KEY_FAC_ALGORITHM = "PBKDF2WithHmacSHA1"

    private val salt = ByteArray(SALT_SIZE_BYTES)

    private val IV: ByteArray = ByteArray(cipher.blockSize)

    init {
        if (Build.VERSION.SDK_INT >= 26) {
            SECRET_KEY_FAC_ALGORITHM = "PBEwithHmacSHA512AndAES_256"
        }
    }

    fun encrypt(input: String, password: String): ByteArray {

        random.nextBytes(salt)

        val keySpec: KeySpec = PBEKeySpec(password.toCharArray(), salt, iterations, KEY_SIZE_BITS)

        val keyFactory: SecretKeyFactory =
                SecretKeyFactory.getInstance(SECRET_KEY_FAC_ALGORITHM)

        val keyBytes = keyFactory.generateSecret(keySpec).encoded
        val key = SecretKeySpec(keyBytes, "AES")

        random.nextBytes(IV)

        val ivParams = IvParameterSpec(IV)

        cipher.init(Cipher.ENCRYPT_MODE, key, ivParams)

        val secure = cipher.doFinal(input.toByteArray(CHARSET))

        val response = Base64.encode(IV, Base64.DEFAULT)
                .plus('&'.toByte())
                .plus(Base64.encode(secure, Base64.DEFAULT))
                .plus('&'.toByte())
                .plus(Base64.encode(salt, Base64.DEFAULT))

        return response

    }

    fun decrypt(input: ByteArray, password: String): String {

        val data = input.toString(CHARSET).split('&')

        val IV = Base64.decode(data[0].toByteArray(CHARSET), Base64.DEFAULT)

        val salt = Base64.decode(data[2].toByteArray(CHARSET), Base64.DEFAULT)

        val secure = Base64.decode(data[1].toByteArray(CHARSET), Base64.DEFAULT)


        val keySpec: KeySpec = PBEKeySpec(password.toCharArray(), salt, iterations, KEY_SIZE_BITS)

        val keyFactory: SecretKeyFactory =
                SecretKeyFactory.getInstance(SECRET_KEY_FAC_ALGORITHM)

        val keyBytes = keyFactory.generateSecret(keySpec).encoded
        val key = SecretKeySpec(keyBytes, "AES")

        val ivParams = IvParameterSpec(IV)

        cipher.init(Cipher.DECRYPT_MODE, key, ivParams)

        val original = cipher.doFinal(secure)

        return original.toString(CHARSET)
    }

    fun hash() {

    }

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

}

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

package com.pvryan.easycrypt.asymmetric

import com.pvryan.easycrypt.extensions.asString
import com.pvryan.easycrypt.extensions.fromBase64
import com.pvryan.easycrypt.extensions.toBase64String
import java.security.*
import javax.crypto.Cipher

/**
 *
 */
class ECryptAsymmetric {

    private val ASYMMETRIC_ALGORITHM = "RSA"
    private val SIGNATURE_ALGORITHM = "SHA512withRSA"
    private val KEY_SIZE = 2048

    private val cipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM)
    private val random = SecureRandom()

    fun generateKeyPair(): KeyPair {

        val generator = KeyPairGenerator.getInstance(ASYMMETRIC_ALGORITHM)
        generator.initialize(KEY_SIZE, random)
        return generator.generateKeyPair()

    }

    fun encrypt(plainText: String, publicKey: PublicKey): String {

        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val cipherText = cipher.doFinal(plainText.toByteArray())

        return cipherText.toBase64String()
    }

    fun decrypt(cipherText: String, privateKey: PrivateKey): String {

        val bytes = cipherText.toByteArray().fromBase64()
        cipher.init(Cipher.DECRYPT_MODE, privateKey)

        return cipher.doFinal(bytes).asString()
    }

    fun sign(plainText: String, privateKey: PrivateKey): String {

        val privateSignature = Signature.getInstance(SIGNATURE_ALGORITHM)
        privateSignature.initSign(privateKey)
        privateSignature.update(plainText.toByteArray())

        return privateSignature.sign().toBase64String()
    }

    fun verify(plainText: String, signature: String, publicKey: PublicKey): Boolean {
        val publicSignature = Signature.getInstance(SIGNATURE_ALGORITHM)
        publicSignature.initVerify(publicKey)
        publicSignature.update(plainText.toByteArray())

        val signatureBytes = signature.toByteArray().fromBase64()

        return publicSignature.verify(signatureBytes)
    }

}
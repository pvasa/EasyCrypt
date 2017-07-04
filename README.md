**EasyCrypt - Android Cryptography made easy**

**Usage:**

    val eCrypt = ECrypt()

**Encrypt data:**

    eCrypt.encrypt (input, password,
        object : ECrypt.ECryptResultListener {

            // Optional
            override fun onProgress(progressBy: Int) {

            }

            override fun <T> onSuccess(result: T) {

            }

            override fun onFailure(message: String, e: Exception) {

            }
        },
        outputFile // Optional
    )

**Decrypt data:**

    eCrypt.decrypt(input, password,
            object : ECrypt.ECryptResultListener {

                // Optional
                override fun onProgress(progressBy: Int) {

                }

                override fun <T> onSuccess(result: T) {

                }

                override fun onFailure(message: String, e: Exception) {

                }
            },
            outputFile // Optional
        )

**Hash data:**

    eCrypt.hash(input, hashAlgorithm, // from ECrypt.HashAlgorithms
            object : ECrypt.ECryptResultListener {

                // Optional
                override fun onProgress(progressBy: Int) {

                }

                override fun <T> onSuccess(result: T) {

                }

                override fun onFailure(message: String, e: Exception) {

                }
            },
            outputFile // Optional
        )

------------------------------------------
Input -> Output

File -> outputFile

FileInputStream -> outputFile

ByteArray -> String (outputFile, if provided)

String -> String (outputFile, if provided)

CharSequence -> String (outputFile, if provided)

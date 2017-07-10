**EasyCrypt**
---
Easily encrypt and decrypt data with a password in a very secure way using AES algorithm.
Randomly generated 256 bits keys using PRNG are used in the process.

Or generate hash of input data using any hashing algorithm.

**Usage**
---

    val eCrypt = ECrypt()

**Encrypt data**

    eCrypt.encrypt (input, password,
        object : ECrypt.ECryptResultListener {

            // Optional
            override fun onProgress(newBytes: Int, bytesProcessed: Long) {

            }

            override fun <T> onSuccess(result: T) {

            }

            override fun onFailure(message: String, e: Exception) {

            }
        },
        outputFile // Optional
    )

**Decrypt data**

    eCrypt.decrypt(input, password,
            object : ECrypt.ECryptResultListener {

                // Optional
                override fun onProgress(newBytes: Int, bytesProcessed: Long) {

                }

                override fun <T> onSuccess(result: T) {

                }

                override fun onFailure(message: String, e: Exception) {

                }
            },
            outputFile // Optional
        )

**Hash data**

    eCrypt.hash(input, hashAlgorithm, // from ECrypt.HashAlgorithms
            object : ECrypt.ECryptResultListener {

                // Optional
                override fun onProgress(newBytes: Int, bytesProcessed: Long) {

                }

                override fun <T> onSuccess(result: T) {

                }

                override fun onFailure(message: String, e: Exception) {

                }
            },
            outputFile // Optional
        )

---
| Input           | Output                           |
|-----------------|----------------------------------|
| File            | outputFile                       |
| FileInputStream | outputFile                       |
| ByteArray       | String (outputFile, if provided) |
| String          | String (outputFile, if provided) |
| CharSequence    | String (outputFile, if provided) |

**License**
---

    Copyright 2017 Priyank Vasa
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
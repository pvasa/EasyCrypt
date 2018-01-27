[![CircleCI](https://img.shields.io/circleci/project/github/ryan652/EasyCrypt.svg)](https://circleci.com/gh/ryan652/EasyCrypt)
[![Bintray](https://img.shields.io/github/release/ryan652/easycrypt.svg)](https://github.com/ryan652/EasyCrypt/releases)
[![License](https://img.shields.io/github/license/ryan652/easycrypt.svg)](LICENSE)
[![GitHub issues](https://img.shields.io/github/issues/ryan652/easycrypt.svg)](https://github.com/ryan652/EasyCrypt/issues)

# EasyCrypt
Secure and efficient cryptography library for Android. (Auto fix SecureRandom bugs in API 18 and below.)

## Features
* AES-256 encryption algorithm
* CBC/CTR mode of operations
* Block padding with PKCS7 (only with CBC)
* Computationally secure random salt (of cipher block size)
* Password stretching with PBKDF2
* Random IV generated on each encryption (16 bytes)
* Supports MD5, SHA1, and SHA2 hash functions
* Generate secure keys with SecureRandom or random.org
* Asymmetric encryption with RSA
* Auto handle large data by using hybrid asymmetric encryption
* Asymmetric RSA signing and verification
* Supported RSA key sizes are 2048 bits and 4096 bits
* Password analysis for strength, crack times, weakness, etc using [nulab's zxcvbn4j library](https://github.com/nulab/zxcvbn4j)

## Install
Add in your app's build.gradle
```gradle
dependencies {
    ..
    implementation "com.pvryan.easycrypt:easycrypt:1.3.2"
}
```

## Usage
```kotlin
val eCryptSymmetric = ECSymmetric()
val eCryptAsymmetric = ECAsymmetric()
val eCryptHash = ECHash()
val eCryptPass = ECPasswords()
```

### Symmetric key encryption
#### Encrypt data
```kotlin
eCryptSymmetric.encrypt (input, password,
    object : ECResultListener {

        // Optional
        override fun onProgress(newBytes: Int, bytesProcessed: Long, totalBytes: Long) {

        }

        override fun <T> onSuccess(result: T) {

        }

        override fun onFailure(message: String, e: Exception) {

        }
    },
    outputFile // Optional
)
```

#### Decrypt data
```kotlin
eCryptSymmetric.decrypt(input, password,
        object : ECResultListener {

            // Optional
            override fun onProgress(newBytes: Int, bytesProcessed: Long, totalBytes: Long) {

            }

            override fun <T> onSuccess(result: T) {

            }

            override fun onFailure(message: String, e: Exception) {

            }
        },
        outputFile // Optional
)
```

### Asymmetric key encryption
#### Encrypt data
```kotlin
eCryptAsymmetric.generateKeyPair(object : ECRSAKeyPairListener {

     override fun onSuccess(keyPair: KeyPair) {
         privateKey = keyPair.private as RSAPrivateKey // Save private key
         eCryptAsymmetric.encrypt(input, keyPair.public as RSAPublicKey,
                 object : ECResultListener {

                     // Optional
                     override fun onProgress(newBytes: Int, bytesProcessed: Long, totalBytes: Long) {

                     }

                     override fun <T> onSuccess(result: T) {

                     }

                     override fun onFailure(message: String, e: Exception) {

                     }
                 },
                 outputFile // Optional
         )
     }

     override fun onFailure(message: String, e: Exception) {
         e.printStackTrace()
     }

 }, keySize = eCryptAsymmetric.KeySizes._4096)
```

#### Decrypt data
```kotlin
eCryptAsymmetric.decrypt(input, privateKey,
        object : ECResultListener {

            // Optional
            override fun onProgress(newBytes: Int, bytesProcessed: Long, totalBytes: Long) {

            }

            override fun <T> onSuccess(result: T) {

            }

            override fun onFailure(message: String, e: Exception) {

            }
        },
        outputFile // Optional
)
```

#### Sign data
```kotlin
eCryptKeys.genRSAKeyPair(object : ECRSAKeyPairListener {

    override fun onGenerated(keyPair: KeyPair) {

        publicKey = keyPair.public as RSAPublicKey

        eCryptAsymmetric.sign(input,
                keyPair.private as RSAPrivateKey,
                object : ECResultListener {

                    // Optional
                    override fun onProgress(newBytes: Int, bytesProcessed: Long, totalBytes: Long) {

                    }

                    override fun <T> onSuccess(result: T) {

                    }

                    override fun onFailure(message: String, e: Exception) {

                    }
                },
                signatureOutputFile)
    }

    override fun onFailure(message: String, e: Exception) {

    }
})
```

#### Verify data
```kotlin
eCryptAsymmetric.verify(input, publicKey, signatureFile,
        object : ECVerifiedListener {
            override fun onSuccess(verified: Boolean) {

            }

            override fun onFailure(message: String, e: Exception) {

            }
        }
)
```

#### Hash data
```kotlin
eCryptHash.calculate(input, hashAlgorithm, // from ECHashAlgorithms
        object : ECResultListener {

            // Optional
            override fun onProgress(newBytes: Int, bytesProcessed: Long, totalBytes: Long) {

            }

            override fun <T> onSuccess(result: T) {

            }

            override fun onFailure(message: String, e: Exception) {

            }
        },
        outputFile // Optional
)
```

#### Analyze password
```kotlin
val analysis: ECPasswordAnalysis = ECPasswordAnalyzer.analyze("thisismypassword")
```

--------------------------------------------------------------
| Input                 | Output                             |
|-----------------------|------------------------------------|
| File                  | outputFile                         |
| FileInputStream       | outputFile                         |
| ByteArray             | String or outputFile (if provided) |
| ByteArrayInputStream  | String or outputFile (if provided) |
| String                | String or outputFile (if provided) |
| CharSequence          | String or outputFile (if provided) |
| Anything else         | InvalidParameterException          |

#### Generate key with SecureRandom (pseudo-random)
```kotlin
val password = eCryptPass.genSecureRandomPassword(length, charArrayOf(/*symbols to be used in password*/))
```

#### Generate key with Random.org (true random)
For sample to work enter your API key in FragmentPasswords
```kotlin
eCryptPass.genRandomOrgPassword(
        length,
        "random-org-api-key", //TODO: Replace with your random.org api key
        new ECPasswordListener() {

            @Override
            public void onFailure(@NonNull String message, @NonNull Exception e) {

            }

            @Override
            public void onSuccess(@NonNull String password) {

            }
        });
```

## License
```
Copyright 2018 Priyank Vasa
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
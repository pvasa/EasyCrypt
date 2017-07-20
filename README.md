[![CircleCI](https://img.shields.io/circleci/project/github/ryan652/EasyCrypt.svg)](https://circleci.com/gh/ryan652/EasyCrypt)
[![Bintray](https://img.shields.io/github/release/ryan652/easycrypt.svg)](https://github.com/ryan652/EasyCrypt/releases)
[![License](https://img.shields.io/github/license/ryan652/easycrypt.svg)](LICENSE)
[![GitHub issues](https://img.shields.io/github/issues/ryan652/easycrypt.svg)](https://github.com/ryan652/EasyCrypt/issues)

# EasyCrypt
Easily encrypt, decrypt, or hash data in a very secure way.

## Features
* AES-256 encryption algorithm
* CBC/CTR mode of operations
* Block padding with PKCS7 (only with CBC)
* Computationally secure random salt (of cipher block size)
* Password stretching with PBKDF2
* Random IV generated on each encryption (16 bytes)
* Supports MD5, SHA1, and SHA2 hash functions
* SecureRandom fixes on Android below KitKat
* Generate key manually with SecureRandom or random.org

## Download
Add in your app's build.gradle
```gradle
dependencies {
    ...
    compile "com.pvryan.easycrypt:easycrypt:1.0.4"
    ...
}
```

## Usage
    val eCrypt = ECrypt()

#### Encrypt data
```kotlin
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
```

#### Decrypt data
```kotlin
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
```

#### Hash data
```kotlin
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
```

------------------------------------------------------
| Input           | Output                           |
|-----------------|----------------------------------|
| File            | outputFile                       |
| FileInputStream | outputFile                       |
| ByteArray       | String (outputFile, if provided) |
| String          | String (outputFile, if provided) |
| CharSequence    | String (outputFile, if provided) |

#### Generate key with SecureRandom (pseudo-random)
```kotlin
val password = eCrypt.genSecureRandomPassword(length, charArrayOf(/*symbols to be used in password*/))
```

#### Generate key with Random.org (true random)
```kotlin
eCrypt.genRandomOrgPassword(
        length,
        "random-org-api-key", //TODO: Replace with your random.org api key
        new ECrypt.ECryptPasswordListener() {

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
```
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

package com.pvryan.easycrypt

import android.os.Build
import android.os.Environment
import java.io.File
import java.security.SecureRandom

internal open class Constants {

    companion object {

        val random = SecureRandom()

        val SECRET_KEY_FAC_ALGORITHM =
                if (Build.VERSION.SDK_INT < 26) "PBKDF2WithHmacSHA1"
                else "PBEwithHmacSHA512AndAES_256"

        val SECRET_KEY_SPEC_ALGORITHM = "AES"

        val KEY_BITS_LENGTH = 256
        val SALT_BYTES_LENGTH = KEY_BITS_LENGTH / 8

        val ITERATIONS = 10000

        private val HASH_FILE_EXT = ".txt"
        val ECRYPT_FILE_EXT = ".ecrypt"

        private val HASH_FILE_NAME = "HashOfFile"
        val ENCRYPTED_FILE_NAME = "EncryptedFile"
        private val DECRYPTED_FILE_NAME = "DecryptedFile"

        private val TEMP_DIR_NAME = ".ecrypt"

        val DEF_EXT_TEMP_DIR_PATH =
                Environment.getExternalStorageDirectory().absolutePath +
                        File.separator + TEMP_DIR_NAME

        private val DEF_EXT_FILE_PATH =
                Environment.getExternalStorageDirectory().absolutePath + File.separator

        val DEF_HASH_FILE_PATH = DEF_EXT_FILE_PATH + HASH_FILE_NAME + HASH_FILE_EXT
        val DEF_ENCRYPTED_FILE_PATH = DEF_EXT_FILE_PATH + ENCRYPTED_FILE_NAME + ECRYPT_FILE_EXT
        val DEF_DECRYPTED_FILE_PATH = DEF_EXT_FILE_PATH + DECRYPTED_FILE_NAME + ECRYPT_FILE_EXT

        val MSG_INPUT_TYPE_NOT_SUPPORTED = "Input type not supported."
        val MSG_INVALID_INPUT_DATA = "Invalid input data."
        val MSG_NO_SUCH_FILE = "File does not exist."
        val MSG_CANNOT_WRITE = "Cannot write to file."
        val MSG_CANNOT_READ = "Cannot read from file."
        val MSG_OUTPUT_FILE_EXISTS = "Output file already exists."

        val STANDARD_SYMBOLS =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                        "abcdefghijklmnopqrstuvwxyz" +
                        "0123456789"

        val PASSWORD_LENGTH: Int = 24

    }
}
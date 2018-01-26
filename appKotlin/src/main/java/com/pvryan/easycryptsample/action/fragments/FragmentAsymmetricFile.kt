/**
 * Copyright 2018 Priyank Vasa
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

package com.pvryan.easycryptsample.action.fragments

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.Environment
import android.support.v4.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import com.pvryan.easycrypt.ECKeys
import com.pvryan.easycrypt.ECResultListener
import com.pvryan.easycrypt.asymmetric.ECAsymmetric
import com.pvryan.easycrypt.asymmetric.ECRSAKeyPairListener
import com.pvryan.easycrypt.asymmetric.ECVerifiedListener
import com.pvryan.easycrypt.hash.ECHash
import com.pvryan.easycrypt.hash.ECHashAlgorithms
import com.pvryan.easycrypt.symmetric.ECSymmetric
import com.pvryan.easycryptsample.R
import kotlinx.android.synthetic.main.fragment_asymmetric_file.*
import org.jetbrains.anko.AnkoLogger
import org.jetbrains.anko.support.v4.longToast
import org.jetbrains.anko.support.v4.onUiThread
import org.jetbrains.anko.support.v4.toast
import java.io.File
import java.security.KeyPair
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

class FragmentAsymmetricFile : Fragment(), AnkoLogger, ECResultListener {

    private val _rCHash = 2
    private val _rCEncrypt = 3
    private val _rCDecrypt = 4
    private val _rCSign = 5
    private val _rCVerify = 6
    private val eCryptSymmetric = ECSymmetric()
    private val eCryptAsymmetric = ECAsymmetric()
    private val eCryptHash = ECHash()
    private val eCryptKeys = ECKeys()
    private lateinit var privateKey: RSAPrivateKey
    private lateinit var publicKey: RSAPublicKey

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_asymmetric_file, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        buttonSelectEncryptF.setOnClickListener {
            selectFile(_rCEncrypt)
        }
        buttonSelectDecryptF.setOnClickListener {
            selectFile(_rCDecrypt)
        }
        buttonSignF.setOnClickListener {
            selectFile(_rCSign)
        }
        buttonVerifyF.setOnClickListener {
            selectFile(_rCVerify)
        }
    }

    private fun selectFile(requestCode: Int) {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT)
        intent.addCategory(Intent.CATEGORY_OPENABLE)
        intent.type = "*/*"
        startActivityForResult(intent, requestCode)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {

        if (resultCode == Activity.RESULT_OK) {

            val fis = context?.contentResolver?.openInputStream(data?.data)

            progressBarF.visibility = View.VISIBLE

            when (requestCode) {

                _rCHash -> {
                    eCryptHash.calculate(fis, ECHashAlgorithms.SHA_256, this)
                }

                _rCEncrypt -> {
                    eCryptKeys.genRSAKeyPair(object : ECRSAKeyPairListener {
                        override fun onGenerated(keyPair: KeyPair) {
                            privateKey = keyPair.private as RSAPrivateKey
                            eCryptAsymmetric.encrypt(fis,
                                    keyPair.public as RSAPublicKey, this@FragmentAsymmetricFile)
                        }

                        override fun onFailure(message: String, e: Exception) {
                            e.printStackTrace()
                            onUiThread {
                                progressBarF.visibility = View.INVISIBLE
                                longToast("Error: $message")
                            }
                        }
                    })
                }

                _rCDecrypt -> {
                    eCryptAsymmetric.decrypt(fis, privateKey, this)
                }

                _rCSign -> {
                    val sigFile = File(Environment.getExternalStorageDirectory(),
                            "ECryptSample/sample.sig")
                    if (sigFile.exists()) sigFile.delete()

                    eCryptKeys.genRSAKeyPair(object : ECRSAKeyPairListener {

                        override fun onGenerated(keyPair: KeyPair) {
                            publicKey = keyPair.public as RSAPublicKey
                            eCryptAsymmetric.sign(fis,
                                    keyPair.private as RSAPrivateKey,
                                    this@FragmentAsymmetricFile,
                                    sigFile)
                        }

                        override fun onFailure(message: String, e: Exception) {
                            e.printStackTrace()
                            onUiThread {
                                longToast("Failed to generate RSA key pair. Try again.")
                            }
                        }
                    })
                }

                _rCVerify -> {
                    eCryptAsymmetric.verify(fis, publicKey,
                            File(Environment.getExternalStorageDirectory(), "ECryptSample/sample.sig"),
                            object : ECVerifiedListener {
                                override fun onSuccess(verified: Boolean) {
                                    onUiThread {
                                        if (verified) tvResultF.text = getString(R.string.msg_valid)
                                        else tvResultF.text = getString(R.string.msg_invalid)
                                        progressBarF.visibility = View.INVISIBLE
                                    }
                                }

                                override fun onFailure(message: String, e: Exception) {
                                    e.printStackTrace()
                                    onUiThread {
                                        progressBarF.visibility = View.INVISIBLE
                                        toast("Error: $message")
                                    }
                                }
                            })
                }
            }
        }
    }

    override fun onProgress(newBytes: Int, bytesProcessed: Long) {
        progressBarF.progress = (bytesProcessed / 1024).toInt()
    }

    override fun <T> onSuccess(result: T) {
        onUiThread {
            progressBarF.visibility = View.INVISIBLE
            tvResultF.text = resources.getString(
                    R.string.success_result_to_file,
                    (result as File).absolutePath)
        }
    }

    override fun onFailure(message: String, e: Exception) {
        e.printStackTrace()
        onUiThread {
            progressBarF.visibility = View.INVISIBLE
            toast("Error: $message")
        }
    }

    companion object {
        fun newInstance(): Fragment = FragmentAsymmetricFile()
    }
}

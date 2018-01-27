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
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import com.pvryan.easycrypt.ECKeys
import com.pvryan.easycrypt.ECResultListener
import com.pvryan.easycrypt.asymmetric.ECAsymmetric
import com.pvryan.easycrypt.asymmetric.ECRSAKeyPairListener
import com.pvryan.easycrypt.asymmetric.ECVerifiedListener
import com.pvryan.easycryptsample.R
import com.pvryan.easycryptsample.extensions.hide
import com.pvryan.easycryptsample.extensions.show
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

    private val _rCEncrypt = 2
    private val _rCDecrypt = 3
    private val _rCSign = 4
    private val _rCVerify = 5
    private val eCryptAsymmetric = ECAsymmetric()
    private val eCryptKeys = ECKeys()
    private lateinit var privateKey: RSAPrivateKey
    private lateinit var publicKey: RSAPublicKey

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
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

            progressBarF.show()

            when (requestCode) {

                _rCEncrypt -> {
                    tvStatus.text = getString(R.string.tv_status_encrypting)
                    eCryptKeys.genRSAKeyPair(object : ECRSAKeyPairListener {
                        override fun onGenerated(keyPair: KeyPair) {
                            privateKey = keyPair.private as RSAPrivateKey
                            eCryptAsymmetric.encrypt(fis,
                                    keyPair.public as RSAPublicKey, this@FragmentAsymmetricFile)
                        }

                        override fun onFailure(message: String, e: Exception) {
                            e.printStackTrace()
                            onUiThread {
                                progressBarF.hide()
                                tvStatus.text = getString(R.string.tv_status_idle)
                                longToast("Error: $message")
                            }
                        }
                    })
                }

                _rCDecrypt -> {
                    tvStatus.text = getString(R.string.tv_status_decrypting)
                    eCryptAsymmetric.decrypt(fis, privateKey, this)
                }

                _rCSign -> {
                    tvStatus.text = getString(R.string.tv_status_signing)
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
                                progressBarF.hide()
                                tvStatus.text = getString(R.string.tv_status_idle)
                                longToast("Failed to generate RSA key pair. Try again.")
                            }
                        }
                    })
                }

                _rCVerify -> {
                    tvStatus.text = getString(R.string.tv_status_verifying)
                    eCryptAsymmetric.verify(fis, publicKey,
                            File(Environment.getExternalStorageDirectory(), "ECryptSample/sample.sig"),
                            object : ECVerifiedListener {
                                override fun onSuccess(verified: Boolean) {
                                    onUiThread {
                                        progressBarF.hide()
                                        if (verified) tvResultF.text = getString(R.string.msg_valid)
                                        else tvResultF.text = getString(R.string.msg_invalid)
                                    }
                                }

                                override fun onFailure(message: String, e: Exception) {
                                    e.printStackTrace()
                                    onUiThread {
                                        progressBarF.hide()
                                        tvStatus.text = getString(R.string.tv_status_idle)
                                        toast("Error: $message")
                                    }
                                }
                            })
                }
            }
        }
    }

    private var maxSet = false
    override fun onProgress(newBytes: Int, bytesProcessed: Long, totalBytes: Long) {
        Log.i("TEST", "" + bytesProcessed)
        if (totalBytes > -1) {
            onUiThread {
                if (!maxSet) {
                    progressBarF.isIndeterminate = false
                    progressBarF.max = (totalBytes / 1024).toInt()
                    maxSet = true
                }
                progressBarF.progress = (bytesProcessed / 1024).toInt()
            }
        }
    }

    override fun <T> onSuccess(result: T) {
        onUiThread {
            progressBarF.hide()
            tvStatus.text = getString(R.string.tv_status_idle)
            tvResultF.text = resources.getString(
                    R.string.success_result_to_file,
                    (result as File).absolutePath)
        }
    }

    override fun onFailure(message: String, e: Exception) {
        e.printStackTrace()
        onUiThread {
            progressBarF.hide()
            tvStatus.text = getString(R.string.tv_status_idle)
            toast("Error: $message")
        }
    }

    companion object {
        fun newInstance(): Fragment = FragmentAsymmetricFile()
    }
}

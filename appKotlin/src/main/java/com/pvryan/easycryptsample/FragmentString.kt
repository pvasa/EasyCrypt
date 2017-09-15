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

package com.pvryan.easycryptsample

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.os.Environment
import android.support.annotation.Nullable
import android.support.v4.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.RadioGroup
import com.pvryan.easycrypt.ECKeys
import com.pvryan.easycrypt.ECResultListener
import com.pvryan.easycrypt.asymmetric.ECAsymmetric
import com.pvryan.easycrypt.asymmetric.ECRSAKeyPairListener
import com.pvryan.easycrypt.asymmetric.ECVerifiedListener
import com.pvryan.easycrypt.hash.ECHash
import com.pvryan.easycrypt.hash.ECHashAlgorithms
import com.pvryan.easycrypt.symmetric.ECSymmetric
import kotlinx.android.synthetic.main.fragment_string.*
import org.jetbrains.anko.support.v4.longToast
import org.jetbrains.anko.support.v4.onUiThread
import java.io.File
import java.security.KeyPair
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

class FragmentString : Fragment(), ECResultListener {

    private val eCryptSymmetric = ECSymmetric()
    private val eCryptAsymmetric = ECAsymmetric()
    private val eCryptHash = ECHash()
    private val eCryptKeys = ECKeys()
    private lateinit var privateKey: RSAPrivateKey
    private lateinit var publicKey: RSAPublicKey

    override fun onCreateView(inflater: LayoutInflater?, @Nullable container: ViewGroup?,
                              @Nullable savedInstanceState: Bundle?): View? {
        return inflater?.inflate(R.layout.fragment_string, container, false)
    }

    override fun onViewCreated(view: View?, @Nullable savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        rgTypeS.setOnCheckedChangeListener { _: RadioGroup, id: Int ->
            when (id) {
                R.id.rbSymmetricS -> {
                    edPasswordS.visibility = View.VISIBLE
                    llSignVerifyS.visibility = View.GONE
                }
                R.id.rbAsymmetricS -> {
                    edPasswordS.visibility = View.GONE
                    llSignVerifyS.visibility = View.VISIBLE
                }
            }
        }

        val clipboard = activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        tvResultS.setOnLongClickListener {
            val data = ClipData.newPlainText("result", tvResultS.text)
            clipboard.primaryClip = data
            longToast("Result copied to clipboard")
            true
        }

        buttonHashS.setOnClickListener {
            eCryptHash.calculate(edInputS.text, ECHashAlgorithms.SHA_512, this)
        }

        buttonEncryptS.setOnClickListener {

            progressBarS.visibility = View.VISIBLE

            when (rgTypeS.checkedRadioButtonId) {

                R.id.rbSymmetricS -> {
                    eCryptSymmetric.encrypt(edInputS.text, edPasswordS.text.toString(), this)
                }

                R.id.rbAsymmetricS -> {
                    eCryptKeys.genRSAKeyPair(object : ECRSAKeyPairListener {
                        override fun onGenerated(keyPair: KeyPair) {
                            privateKey = keyPair.private as RSAPrivateKey
                            eCryptAsymmetric.encrypt(edInputS.text.toString(),
                                    keyPair.public as RSAPublicKey, this@FragmentString)
                        }

                        override fun onFailure(message: String, e: Exception) {
                            e.printStackTrace()
                            onUiThread {
                                progressBarS.visibility = View.INVISIBLE
                                longToast("Error: $message")
                            }
                        }
                    })
                }
            }
        }

        buttonDecryptS.setOnClickListener {

            when (rgTypeS.checkedRadioButtonId) {

                R.id.rbSymmetricS -> {
                    eCryptSymmetric.decrypt(edInputS.text, edPasswordS.text.toString(), this)
                }

                R.id.rbAsymmetricS -> {
                    eCryptAsymmetric.decrypt(edInputS.text, privateKey, this)
                }
            }
        }

        buttonSignS.setOnClickListener {

            val sigFile = File(Environment.getExternalStorageDirectory(),
                    "ECryptSample/sample.sig")
            if (sigFile.exists()) sigFile.delete()

            eCryptKeys.genRSAKeyPair(object : ECRSAKeyPairListener {

                override fun onGenerated(keyPair: KeyPair) {
                    publicKey = keyPair.public as RSAPublicKey
                    eCryptAsymmetric.sign(edInputS.text,
                            keyPair.private as RSAPrivateKey,
                            this@FragmentString,
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

        buttonVerifyS.setOnClickListener {

            eCryptAsymmetric.verify(edInputS.text.toString(), publicKey,
                    File(Environment.getExternalStorageDirectory(), "ECryptSample/sample.sig"),
                    object : ECVerifiedListener {
                        override fun onSuccess(verified: Boolean) {
                            onUiThread {
                                if (verified) tvResultS.text = getString(R.string.msg_valid)
                                else tvResultS.text = getString(R.string.msg_invalid)
                            }
                        }

                        override fun onFailure(message: String, e: Exception) {
                            e.printStackTrace()
                            onUiThread {
                                progressBarS.visibility = View.INVISIBLE
                                longToast("Error: $message")
                            }
                        }

                    })
        }
    }

    companion object {
        fun newInstance(): Fragment = FragmentString()
    }

    override fun <T> onSuccess(result: T) {
        onUiThread {
            progressBarS.visibility = View.INVISIBLE
            tvResultS.text = when (result) {

                is File -> resources.getString(
                        R.string.success_result_to_file,
                        (result as File).absolutePath)

                is String -> result

                else -> "Undefined"
            }
        }
    }

    override fun onFailure(message: String, e: Exception) {
        e.printStackTrace()
        onUiThread {
            progressBarS.visibility = View.INVISIBLE
            longToast("Error: $message")
        }
    }
}

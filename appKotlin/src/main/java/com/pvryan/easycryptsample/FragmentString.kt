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
import android.support.annotation.Nullable
import android.support.v4.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.RadioGroup
import com.pvryan.easycrypt.ECryptResultListener
import com.pvryan.easycrypt.asymmetric.ECryptAsymmetric
import com.pvryan.easycrypt.asymmetric.ECryptRSAKeyPairListener
import com.pvryan.easycrypt.hash.ECryptHash
import com.pvryan.easycrypt.hash.ECryptHashAlgorithms
import com.pvryan.easycrypt.symmetric.ECryptSymmetric
import kotlinx.android.synthetic.main.fragment_string.*
import org.jetbrains.anko.support.v4.longToast
import org.jetbrains.anko.support.v4.onUiThread
import java.security.KeyPair
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

class FragmentString : Fragment(), ECryptResultListener {

    private val eCryptSymmetric = ECryptSymmetric()
    private val eCryptAsymmetric = ECryptAsymmetric()
    private val eCryptHash = ECryptHash()
    private lateinit var privateKey: RSAPrivateKey

    override fun onCreateView(inflater: LayoutInflater?, @Nullable container: ViewGroup?,
                              @Nullable savedInstanceState: Bundle?): View? {
        return inflater?.inflate(R.layout.fragment_string, container, false)
    }

    override fun onViewCreated(view: View?, @Nullable savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        rgTypeS.setOnCheckedChangeListener { _: RadioGroup, id: Int ->
            when (id) {
                R.id.rbSymmetricS -> edPasswordS.visibility = View.VISIBLE
                R.id.rbAsymmetricS -> edPasswordS.visibility = View.GONE
            }
        }

        val clipboard = activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        tvResultS.setOnLongClickListener {
            val data = ClipData.newPlainText("result", tvResultS.text)
            clipboard.primaryClip = data
            longToast("Result copied to clipboard")
            true
        }

        buttonEncryptS.setOnClickListener {

            progressBarS.visibility = View.VISIBLE

            when (rgTypeS.checkedRadioButtonId) {

                R.id.rbSymmetricS -> {
                    eCryptSymmetric.encrypt(edInputS.text, edPasswordS.text.toString(), this)
                }

                R.id.rbAsymmetricS -> {
                    eCryptAsymmetric.generateKeyPair(object : ECryptRSAKeyPairListener {
                        override fun onSuccess(keyPair: KeyPair) {
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

        buttonHashS.setOnClickListener {
            eCryptHash.calculate(edInputS.text, ECryptHashAlgorithms.SHA_512, this)
        }
    }

    companion object {
        fun newInstance(): Fragment = FragmentString()
    }

    override fun <T> onSuccess(result: T) {
        onUiThread {
            progressBarS.visibility = View.INVISIBLE
            tvResultS.text = result as String
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

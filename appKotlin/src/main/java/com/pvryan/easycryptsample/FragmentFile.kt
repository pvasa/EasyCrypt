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

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.support.annotation.Nullable
import android.support.v4.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import com.pvryan.easycrypt.ECryptResultListener
import com.pvryan.easycrypt.asymmetric.ECryptAsymmetric
import com.pvryan.easycrypt.asymmetric.ECryptRSAKeyPairListener
import com.pvryan.easycrypt.hash.ECryptHash
import com.pvryan.easycrypt.hash.ECryptHashAlgorithms
import com.pvryan.easycrypt.symmetric.ECryptSymmetric
import kotlinx.android.synthetic.main.fragment_file.*
import org.jetbrains.anko.AnkoLogger
import org.jetbrains.anko.support.v4.longToast
import org.jetbrains.anko.support.v4.onUiThread
import org.jetbrains.anko.support.v4.toast
import java.io.File
import java.security.KeyPair
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

class FragmentFile : Fragment(), AnkoLogger, ECryptResultListener {

    private val RC_HASH = 2
    private val RC_ENCRYPT = 3
    private val RC_DECRYPT = 4
    private val eCryptSymmetric = ECryptSymmetric()
    private val eCryptAsymmetric = ECryptAsymmetric()
    private lateinit var privateKey: RSAPrivateKey
    private val eCryptHash = ECryptHash()

    override fun onCreateView(inflater: LayoutInflater?, @Nullable container: ViewGroup?,
                              @Nullable savedInstanceState: Bundle?): View? {
        return inflater?.inflate(R.layout.fragment_file, container, false)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
    }

    override fun onViewCreated(view: View?, @Nullable savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        rgTypeF.setOnCheckedChangeListener { _, id ->
            when (id) {
                R.id.rbSymmetricF -> edPasswordF.visibility = View.VISIBLE
                R.id.rbAsymmetricF -> edPasswordF.visibility = View.GONE
            }
        }

        buttonSelectHashF.setOnClickListener {
            selectFile(RC_HASH)
        }
        buttonSelectEncryptF.setOnClickListener {
            selectFile(RC_ENCRYPT)
        }
        buttonSelectDecryptF.setOnClickListener {
            selectFile(RC_DECRYPT)
        }
    }

    fun selectFile(requestCode: Int) {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT)
        intent.addCategory(Intent.CATEGORY_OPENABLE)
        intent.type = "*/*"
        startActivityForResult(intent, requestCode)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {

        if (resultCode == Activity.RESULT_OK) {

            val fis = context.contentResolver.openInputStream(data?.data)

            when (requestCode) {

                RC_HASH -> {
                    eCryptHash.calculate(fis, ECryptHashAlgorithms.SHA_256, this)
                }

                RC_ENCRYPT -> {
                    when (rgTypeF.checkedRadioButtonId) {

                        R.id.rbSymmetricF ->
                            eCryptSymmetric.encrypt(fis, edPasswordF.text.toString(), this)

                        R.id.rbAsymmetricF -> {
                            eCryptAsymmetric.generateKeyPair(object : ECryptRSAKeyPairListener {
                                override fun onSuccess(keyPair: KeyPair) {
                                    privateKey = keyPair.private as RSAPrivateKey
                                    eCryptAsymmetric.encrypt(fis,
                                            keyPair.public as RSAPublicKey, this@FragmentFile)
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
                    }
                }

                RC_DECRYPT -> {
                    when (rgTypeF.checkedRadioButtonId) {

                        R.id.rbSymmetricF ->
                            eCryptSymmetric.decrypt(fis, edPasswordF.text.toString(), this)

                        R.id.rbAsymmetricF -> eCryptAsymmetric.decrypt(fis, privateKey, this)
                    }
                }
            }
        }
    }

    companion object {
        fun newInstance(): Fragment = FragmentFile()
    }

    override fun onProgress(newBytes: Int, bytesProcessed: Long) {
        progressBarF.progress = (bytesProcessed / 1024).toInt()
    }

    override fun <T> onSuccess(result: T) {
        onUiThread {
            progressBarF.visibility = View.INVISIBLE
            tvResultF.text = resources.getString(
                    R.string.success_file_decrypted,
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

}
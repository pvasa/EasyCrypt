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

import android.os.Bundle
import android.support.annotation.Nullable
import android.support.v4.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import com.pvryan.easycrypt.ECrypt
import com.pvryan.easycrypt.ECryptHashAlgorithms
import kotlinx.android.synthetic.main.fragment_string.*
import org.jetbrains.anko.support.v4.indeterminateProgressDialog
import org.jetbrains.anko.support.v4.onUiThread
import org.jetbrains.anko.support.v4.toast
import java.io.File

class FragmentString : Fragment() {

    private val eCrypt = ECrypt()

    override fun onCreateView(inflater: LayoutInflater?, @Nullable container: ViewGroup?,
                              @Nullable savedInstanceState: Bundle?): View? {
        return inflater?.inflate(R.layout.fragment_string, container, false)
    }

    override fun onViewCreated(view: View?, @Nullable savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        buttonEncrypt.setOnClickListener {

            val pDialog = indeterminateProgressDialog("Encrypting...")

            eCrypt.encrypt(edInput.text, edPassword.text.toString(),
                    object : ECrypt.ECryptResultListener {

                        override fun <T> onSuccess(result: T) {
                            onUiThread {
                                pDialog.dismiss()
                                tvResult.text = result as String
                            }
                        }

                        override fun onFailure(message: String, e: Exception) {
                            e.printStackTrace()
                            onUiThread {
                                pDialog.dismiss()
                                toast("Error: $message")
                            }
                        }
                    }
            )
        }

        buttonDecrypt.setOnClickListener {

            val pDialog = indeterminateProgressDialog("Decrypting...")

            eCrypt.decrypt(edInput.text, edPassword.text.toString(),
                    object : ECrypt.ECryptResultListener {

                        override fun <T> onSuccess(result: T) {
                            onUiThread {
                                pDialog.dismiss()
                                tvResult.text = result as String
                            }
                        }

                        override fun onFailure(message: String, e: Exception) {
                            e.printStackTrace()
                            onUiThread {
                                pDialog.dismiss()
                                toast("Error: $message")
                            }
                        }

                    }
            )
        }

        buttonHash.setOnClickListener {

            eCrypt.hash(edInput.text, ECryptHashAlgorithms.SHA_256,
                    erl = object : ECrypt.ECryptResultListener {
                        override fun <T> onSuccess(result: T) {
                            onUiThread {
                                tvResult.text = resources.getString(
                                        R.string.success_file_hashed,
                                        (result as File).absolutePath)
                            }
                        }

                        override fun onFailure(message: String, e: Exception) {
                            e.printStackTrace()
                            onUiThread { toast("Error: $message") }
                        }
                    }
            )
        }
    }

    companion object {
        fun newInstance(): Fragment = FragmentString()
    }

}
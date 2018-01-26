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

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.support.v4.app.Fragment
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import com.pvryan.easycrypt.ECKeys
import com.pvryan.easycrypt.symmetric.ECPasswordListener
import com.pvryan.easycryptsample.R
import kotlinx.android.synthetic.main.fragment_generate_password.*
import org.jetbrains.anko.support.v4.longToast
import org.jetbrains.anko.support.v4.toast
import java.security.InvalidParameterException

class FragmentGeneratePassword : Fragment() {

    private val eCPasswords = ECKeys()

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_generate_password, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val clipboard = activity?.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        tvResultP.setOnLongClickListener {
            val data = ClipData.newPlainText("result", tvResultP.text)
            clipboard.primaryClip = data
            longToast("Result copied to clipboard")
            true
        }

        buttonSecureRandomP.setOnClickListener {
            try {
                val symbols: String = edCharsP.text.toString()
                if (symbols.isNotEmpty()) {
                    tvResultP.text = eCPasswords.genSecureRandomPassword(
                            Integer.valueOf(edLengthP.text.toString()),
                            symbols.toCharArray())
                } else {
                    tvResultP.text = eCPasswords.genSecureRandomPassword(
                            Integer.valueOf(edLengthP.text.toString()))
                }
            } catch (e: InvalidParameterException) {
                e.printStackTrace()
                toast(e.localizedMessage)
            } catch (e: NumberFormatException) {
                e.printStackTrace()
                toast("Too big number.")
            }
        }

        buttonRandomOrgP.setOnClickListener {
            try {
                eCPasswords.genRandomOrgPassword(
                        Integer.valueOf(edLengthP.text.toString())!!,
                        "",
                        object : ECPasswordListener {

                            override fun onFailure(message: String, e: Exception) {
                                Log.w(FragmentGeneratePassword::class.java.simpleName, message)
                                e.printStackTrace()
                                toast(e.localizedMessage)
                            }

                            override fun onGenerated(password: String) {
                                tvResultP.text = password
                            }
                        })
            } catch (e: NumberFormatException) {
                e.printStackTrace()
                toast("Too big number.")
            }
        }
    }

    companion object {
        fun newInstance(): Fragment = FragmentGeneratePassword()
    }
}

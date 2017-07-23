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
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import com.pvryan.easycrypt.ECryptPasswordListener
import com.pvryan.easycrypt.ECryptPasswords
import kotlinx.android.synthetic.main.fragment_password.*
import org.jetbrains.anko.support.v4.toast
import java.security.InvalidParameterException

class FragmentPassword : Fragment() {

    private val eCryptPasswords = ECryptPasswords()

    override fun onCreateView(inflater: LayoutInflater?, @Nullable container: ViewGroup?,
                              @Nullable savedInstanceState: Bundle?): View? {
        return inflater?.inflate(R.layout.fragment_password, container, false)
    }

    override fun onViewCreated(view: View?, @Nullable savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        buttonSecureRandom.setOnClickListener {
            try {
                val symbols: String = edChars.text.toString()
                if (symbols.isNotEmpty()) {
                    tvResult.text = eCryptPasswords.genSecureRandomPassword(
                            Integer.valueOf(edLength.text.toString()),
                            symbols.toCharArray())
                } else {
                    tvResult.text = eCryptPasswords.genSecureRandomPassword(
                            Integer.valueOf(edLength.text.toString()))
                }
            } catch (e: InvalidParameterException) {
                e.printStackTrace()
                toast(e.localizedMessage)
            } catch (e: NumberFormatException) {
                e.printStackTrace()
                toast("Too big number.")
            }
        }

        buttonRandomOrg.setOnClickListener {
            try {
                eCryptPasswords.genRandomOrgPassword(
                        Integer.valueOf(edLength.text.toString())!!,
                        "",
                        object : ECryptPasswordListener {

                            override fun onFailure(message: String, e: Exception) {
                                Log.w(FragmentPassword::class.java.simpleName, message)
                                e.printStackTrace()
                                toast(e.localizedMessage)
                            }

                            override fun onSuccess(password: String) {
                                tvResult.text = password
                            }
                        })
            } catch (e: NumberFormatException) {
                e.printStackTrace()
                toast("Too big number.")
            }

        }

    }

    companion object {
        fun newInstance(): Fragment = FragmentPassword()
    }

}
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

import android.animation.ObjectAnimator
import android.annotation.SuppressLint
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.support.annotation.Nullable
import android.support.v4.app.Fragment
import android.text.Editable
import android.text.TextWatcher
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
import com.pvryan.easycrypt.ECKeys
import com.pvryan.easycrypt.symmetric.ECPasswordAnalyzer
import com.pvryan.easycrypt.symmetric.ECPasswordListener
import kotlinx.android.synthetic.main.fragment_password.*
import org.jetbrains.anko.support.v4.longToast
import org.jetbrains.anko.support.v4.toast
import java.security.InvalidParameterException
import java.util.*

class FragmentPassword : Fragment() {

    private val eCPasswords = ECKeys()

    override fun onCreateView(inflater: LayoutInflater?, @Nullable container: ViewGroup?,
                              @Nullable savedInstanceState: Bundle?): View? {
        return inflater?.inflate(R.layout.fragment_password, container, false)
    }

    override fun onViewCreated(view: View?, @Nullable savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        edPasswordP.setOnFocusChangeListener { _, isFocused ->
            if (isFocused) llAnalysis.visibility = View.VISIBLE
            else llAnalysis.visibility = View.GONE
        }

        val clipboard = activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        tvResultP.setOnLongClickListener {
            val data = ClipData.newPlainText("result", tvResultP.text)
            clipboard.primaryClip = data
            longToast("Result copied to clipboard")
            true
        }

        edPasswordP.addTextChangedListener(object : TextWatcher {

            @SuppressLint("SetTextI18n")
            override fun afterTextChanged(newText: Editable?) {

                newText?.toString()?.let {
                    val analysis = ECPasswordAnalyzer.analyze(it)
                    val animation = ObjectAnimator.ofInt(
                            progressBarP, "progress",
                            analysis.strength.value * 100)
                    animation.duration = 500 // 0.5 second
                    animation.interpolator = DecelerateInterpolator()
                    animation.start()

                    tvGuesses.text = String.format(Locale.CANADA, "%.4f", analysis.guesses)
                    tvGuessesLog10.text = String.format(Locale.CANADA, "%.4f", analysis.guessesLog10)
                    tvCalcTime.text = analysis.calcTime.toString() + " ms"
                    tvOnlineBFTime.text = String.format(Locale.CANADA, "%.4f",
                            analysis.crackTimeSeconds.onlineThrottling100perHour) +
                            " secs" + " (" + analysis.crackTimesDisplay.onlineThrottling100perHour + ")"
                    tvOfflineBFTime.text = String.format(Locale.CANADA, "%.4f",
                            analysis.crackTimeSeconds.offlineFastHashing1e10PerSecond) +
                            " secs" + " (" + analysis.crackTimesDisplay.offlineFastHashing1e10PerSecond + ")"
                    tvWarning.text = analysis.feedback.warning
                }
            }

            override fun beforeTextChanged(text: CharSequence?, p1: Int, p2: Int, p3: Int) {}

            override fun onTextChanged(text: CharSequence?, p1: Int, p2: Int, p3: Int) {}
        })

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
                                Log.w(FragmentPassword::class.java.simpleName, message)
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
        fun newInstance(): Fragment = FragmentPassword()
    }

}

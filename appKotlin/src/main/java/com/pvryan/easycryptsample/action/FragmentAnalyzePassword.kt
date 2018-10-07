/*
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
package com.pvryan.easycryptsample.action

import android.animation.ObjectAnimator
import android.annotation.SuppressLint
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
import androidx.fragment.app.Fragment
import com.pvryan.easycrypt.symmetric.ECPasswordAnalyzer
import com.pvryan.easycryptsample.R
import kotlinx.android.synthetic.main.fragment_analyze_password.edPasswordP
import kotlinx.android.synthetic.main.fragment_analyze_password.progressBarP
import kotlinx.android.synthetic.main.fragment_analyze_password.tvCalcTime
import kotlinx.android.synthetic.main.fragment_analyze_password.tvGuesses
import kotlinx.android.synthetic.main.fragment_analyze_password.tvGuessesLog10
import kotlinx.android.synthetic.main.fragment_analyze_password.tvOfflineBFTime
import kotlinx.android.synthetic.main.fragment_analyze_password.tvOnlineBFTime
import kotlinx.android.synthetic.main.fragment_analyze_password.tvWarning
import java.util.*

class FragmentAnalyzePassword : Fragment() {

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_analyze_password, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

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
    }

    companion object {
        fun newInstance(): Fragment = FragmentAnalyzePassword()
    }
}

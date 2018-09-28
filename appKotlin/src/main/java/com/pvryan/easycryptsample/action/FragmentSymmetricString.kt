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

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import com.pvryan.easycrypt.symmetric.ECSymmetric
import com.pvryan.easycryptsample.Constants
import com.pvryan.easycryptsample.R
import com.pvryan.easycryptsample.extensions.hide
import com.pvryan.easycryptsample.extensions.setOnClickEndDrawableListener
import com.pvryan.easycryptsample.extensions.show
import com.pvryan.easycryptsample.extensions.snackLong
import kotlinx.android.synthetic.main.fragment_symmetric_string.buttonDecryptS
import kotlinx.android.synthetic.main.fragment_symmetric_string.buttonEncryptS
import kotlinx.android.synthetic.main.fragment_symmetric_string.edInputS
import kotlinx.android.synthetic.main.fragment_symmetric_string.edPasswordS
import kotlinx.android.synthetic.main.fragment_symmetric_string.llContentSString
import kotlinx.android.synthetic.main.fragment_symmetric_string.progressBarS
import kotlinx.android.synthetic.main.fragment_symmetric_string.tvResultS

class FragmentSymmetricString : Fragment() {

    private val eCryptSymmetric = ECSymmetric()

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_symmetric_string, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        edInputS.setOnClickEndDrawableListener {
            llContentSString.snackLong(getString(R.string.scanComingSoon, "encrypt"))
        }

        buttonEncryptS.setOnClickListener {
            if (edPasswordS.text.toString().isNotBlank()) {
                progressBarS.show()
                eCryptSymmetric
                        .encrypt<String>(edInputS.text?.toString().orEmpty(), edPasswordS.text.toString())
                        .onSuccess(::onSuccess)
                        .onFailure(::onFailure)
            } else view.snackLong("Password cannot be empty!")
        }

        buttonDecryptS.setOnClickListener {
            if (edPasswordS.text.toString().isNotBlank()) {
                progressBarS.show()
                eCryptSymmetric
                        .decrypt<String>(edInputS.text?.toString().orEmpty(), edPasswordS.text.toString())
                        .onSuccess(::onSuccess)
                        .onFailure(::onFailure)
            } else view.snackLong("Password cannot be empty!")
        }

        val clipboard = activity?.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        tvResultS.setOnLongClickListener {
            val data = ClipData.newPlainText("result", tvResultS.text)
            clipboard.primaryClip = data
            view.snackLong("Result copied to clipboard")
            true
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        when (requestCode) {
            Constants.rCCameraResult -> {
                data?.let { edInputS.setText(it.getStringExtra(Constants.INPUT_STRING) ?: "") }
            }
        }
    }

    private fun onSuccess(result: String) {
        progressBarS.hide()
        tvResultS.text = result
    }

    private fun onFailure(message: String, e: Throwable) {
        e.printStackTrace()
        progressBarS.hide()
        llContentSString.snackLong("Error: $message")
    }

    companion object {
        fun newInstance(): Fragment = FragmentSymmetricString()
    }
}

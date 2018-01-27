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
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import com.pvryan.easycrypt.ECResultListener
import com.pvryan.easycrypt.symmetric.ECSymmetric
import com.pvryan.easycryptsample.R
import com.pvryan.easycryptsample.extensions.hide
import com.pvryan.easycryptsample.extensions.show
import com.pvryan.easycryptsample.extensions.snackShort
import kotlinx.android.synthetic.main.fragment_symmetric_string.*
import org.jetbrains.anko.support.v4.longToast
import org.jetbrains.anko.support.v4.onUiThread

class FragmentSymmetricString : Fragment(), ECResultListener {

    private val eCryptSymmetric = ECSymmetric()

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_symmetric_string, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val clipboard = activity?.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        tvResultS.setOnLongClickListener {
            val data = ClipData.newPlainText("result", tvResultS.text)
            clipboard.primaryClip = data
            longToast("Result copied to clipboard")
            true
        }

        buttonEncryptS.setOnClickListener {
            if (edPasswordS.text.toString() != "") {
                progressBarS.show()
                eCryptSymmetric.encrypt(edInputS.text, edPasswordS.text.toString(), this)
            } else view.snackShort("Password cannot be empty!")
        }

        buttonDecryptS.setOnClickListener {
            if (edPasswordS.text.toString() != "") {
                progressBarS.show()
                eCryptSymmetric.decrypt(edInputS.text, edPasswordS.text.toString(), this)
            } else view.snackShort("Password cannot be empty!")
        }
    }

    override fun <T> onSuccess(result: T) {
        onUiThread {
            progressBarS.hide()
            tvResultS.text = result as String
        }
    }

    override fun onFailure(message: String, e: Exception) {
        e.printStackTrace()
        onUiThread {
            progressBarS.hide()
            longToast("Error: $message")
        }
    }

    companion object {
        fun newInstance(): Fragment = FragmentSymmetricString()
    }
}

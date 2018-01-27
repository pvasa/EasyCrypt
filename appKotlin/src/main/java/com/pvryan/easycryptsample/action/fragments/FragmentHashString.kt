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
import android.widget.ArrayAdapter
import com.pvryan.easycrypt.ECResultListener
import com.pvryan.easycrypt.hash.ECHash
import com.pvryan.easycrypt.hash.ECHashAlgorithms
import com.pvryan.easycryptsample.R
import kotlinx.android.synthetic.main.fragment_hash_string.*
import org.jetbrains.anko.support.v4.longToast
import org.jetbrains.anko.support.v4.onUiThread

class FragmentHashString : Fragment(), ECResultListener {

    private val eCryptHash = ECHash()

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_hash_string, container, false)
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

        val hashAdapter: ArrayAdapter<ECHashAlgorithms> = ArrayAdapter(view.context,
                android.R.layout.simple_spinner_item,
                arrayListOf(ECHashAlgorithms.SHA_512,
                        ECHashAlgorithms.SHA_384,
                        ECHashAlgorithms.SHA_256,
                        ECHashAlgorithms.SHA_224,
                        ECHashAlgorithms.SHA_1,
                        ECHashAlgorithms.MD5))
        hashAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        spinnerHashS.adapter = hashAdapter

        buttonHashS.setOnClickListener {
            eCryptHash.calculate(edInputS.text, spinnerHashS.selectedItem as ECHashAlgorithms, this)
        }
    }

    companion object {
        fun newInstance(): Fragment = FragmentHashString()
    }

    override fun <T> onSuccess(result: T) {
        onUiThread {
            tvResultS.text = result as String
        }
    }

    override fun onFailure(message: String, e: Exception) {
        e.printStackTrace()
        onUiThread {
            longToast("Error: $message")
        }
    }
}

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
import android.widget.ArrayAdapter
import androidx.fragment.app.Fragment
import com.pvryan.easycrypt.hash.ECHash
import com.pvryan.easycrypt.hash.ECHashAlgorithms
import com.pvryan.easycryptsample.Constants
import com.pvryan.easycryptsample.R
import com.pvryan.easycryptsample.extensions.setOnClickEndDrawableListener
import com.pvryan.easycryptsample.extensions.snackLong
import kotlinx.android.synthetic.main.fragment_hash_string.buttonHashS
import kotlinx.android.synthetic.main.fragment_hash_string.edInputS
import kotlinx.android.synthetic.main.fragment_hash_string.llContentHString
import kotlinx.android.synthetic.main.fragment_hash_string.spinnerHashS
import kotlinx.android.synthetic.main.fragment_hash_string.tvResultS

class FragmentHashString : Fragment() {

    private val eCryptHash = ECHash()

    override fun onCreateView(
            inflater: LayoutInflater,
            container: ViewGroup?,
            savedInstanceState: Bundle?
    ): View? = inflater.inflate(R.layout.fragment_hash_string, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        edInputS.setOnClickEndDrawableListener {
            llContentHString.snackLong(getString(R.string.scanComingSoon, "hash"))
        }

        val hashAdapter: ArrayAdapter<ECHashAlgorithms> = ArrayAdapter(view.context,
                android.R.layout.simple_spinner_item,
                arrayListOf(
                        ECHashAlgorithms.SHA_512,
                        ECHashAlgorithms.SHA_384,
                        ECHashAlgorithms.SHA_256,
                        ECHashAlgorithms.SHA_224,
                        ECHashAlgorithms.SHA_1,
                        ECHashAlgorithms.MD5))
        hashAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        spinnerHashS.adapter = hashAdapter

        buttonHashS.setOnClickListener {
            eCryptHash
                    .calculate<String>(edInputS.text?.toString().orEmpty(), spinnerHashS.selectedItem as ECHashAlgorithms)
                    .onSuccess { result -> tvResultS.text = result }
                    .onFailure { message, e ->
                        e.printStackTrace()
                        llContentHString.snackLong("Error: $message")
                    }
        }

        val clipboard = activity?.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        tvResultS.setOnLongClickListener {
            clipboard.primaryClip = ClipData.newPlainText("result", tvResultS.text)
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

    companion object {
        fun newInstance(): Fragment = FragmentHashString()
    }
}

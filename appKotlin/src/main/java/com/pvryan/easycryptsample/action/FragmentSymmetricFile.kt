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

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import com.pvryan.easycrypt.symmetric.ECSymmetric
import com.pvryan.easycryptsample.R
import com.pvryan.easycryptsample.extensions.hide
import com.pvryan.easycryptsample.extensions.show
import com.pvryan.easycryptsample.extensions.snackLong
import com.pvryan.easycryptsample.extensions.snackShort
import kotlinx.android.synthetic.main.fragment_symmetric_file.buttonSelectDecryptF
import kotlinx.android.synthetic.main.fragment_symmetric_file.buttonSelectEncryptF
import kotlinx.android.synthetic.main.fragment_symmetric_file.edPasswordF
import kotlinx.android.synthetic.main.fragment_symmetric_file.llContentSFile
import kotlinx.android.synthetic.main.fragment_symmetric_file.progressBarF
import kotlinx.android.synthetic.main.fragment_symmetric_file.tvResultF
import kotlinx.android.synthetic.main.fragment_symmetric_file.tvStatus
import java.io.File

class FragmentSymmetricFile : Fragment() {

    private val _rCEncrypt = 2
    private val _rCDecrypt = 3
    private val eCryptSymmetric = ECSymmetric()

    override fun onCreateView(
            inflater: LayoutInflater,
            container: ViewGroup?,
            savedInstanceState: Bundle?
    ): View? = inflater.inflate(R.layout.fragment_symmetric_file, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        buttonSelectEncryptF.setOnClickListener {
            if (edPasswordF.text.toString().isNotBlank()) selectFile(_rCEncrypt)
            else view.snackShort("Password cannot be empty!")
        }
        buttonSelectDecryptF.setOnClickListener {
            if (edPasswordF.text.toString().isNotBlank()) selectFile(_rCDecrypt)
            else view.snackShort("Password cannot be empty!")
        }
    }

    private fun selectFile(requestCode: Int) {
        Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }.also { startActivityForResult(it, requestCode) }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {

        if (resultCode == Activity.RESULT_OK) {

            val fis = context?.contentResolver?.openInputStream(data?.data) ?: return

            progressBarF.show()

            when (requestCode) {
                _rCEncrypt -> {
                    tvStatus.text = resources.getString(R.string.tv_status_encrypting)
                    eCryptSymmetric
                            .encrypt<File>(fis, edPasswordF.text.toString())
                            .onProgress(::onProgress)
                            .onSuccess(::onSuccess)
                            .onFailure(::onFailure)
                }
                _rCDecrypt -> {
                    tvStatus.text = resources.getString(R.string.tv_status_decrypting)
                    eCryptSymmetric
                            .decrypt<File>(fis, edPasswordF.text.toString())
                            .onProgress(::onProgress)
                            .onSuccess(::onSuccess)
                            .onFailure(::onFailure)
                }
            }
        }
    }

    private var maxSet = false
    private fun onProgress(newBytes: Int, bytesProcessed: Long, totalBytes: Long) {
        if (totalBytes > -1) {
            if (!maxSet) {
                progressBarF.isIndeterminate = false
                progressBarF.max = (totalBytes / 1024).toInt()
                maxSet = true
            }
            progressBarF.progress = (bytesProcessed / 1024).toInt()
        }
    }

    private fun onSuccess(result: File) {
        progressBarF.hide()
        tvStatus.text = getString(R.string.tv_status_idle)
        tvResultF.text = resources.getString(R.string.success_result_to_file, result.absolutePath)
    }

    private fun onFailure(message: String, e: Throwable) {
        e.printStackTrace()
        progressBarF.hide()
        tvStatus.text = getString(R.string.tv_status_idle)
        llContentSFile.snackLong("Error: $message")
    }

    companion object {
        fun newInstance(): Fragment = FragmentSymmetricFile()
    }
}

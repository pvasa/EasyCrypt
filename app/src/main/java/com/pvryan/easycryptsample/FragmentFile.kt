package com.pvryan.easycryptsample

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.support.annotation.Nullable
import android.support.v4.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import com.pvryan.easycrypt.ECrypt
import kotlinx.android.synthetic.main.fragment_file.*
import org.jetbrains.anko.AnkoLogger
import org.jetbrains.anko.support.v4.indeterminateProgressDialog
import org.jetbrains.anko.support.v4.onUiThread
import org.jetbrains.anko.support.v4.toast
import java.io.File
import java.io.FileNotFoundException

class FragmentFile : Fragment(), AnkoLogger {

    private val RC_HASH = 2
    private val RC_ENCRYPT = 3
    private val RC_DECRYPT = 4
    private val eCrypt = ECrypt()

    override fun onCreateView(inflater: LayoutInflater?, @Nullable container: ViewGroup?,
                              @Nullable savedInstanceState: Bundle?): View? {
        return inflater?.inflate(R.layout.fragment_file, container, false)
    }

    override fun onViewCreated(view: View?, @Nullable savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        buttonSelectHash.setOnClickListener {
            selectFile(RC_HASH)
        }
        buttonSelectEncrypt.setOnClickListener {
            selectFile(RC_ENCRYPT)
        }
        buttonSelectDecrypt.setOnClickListener {
            selectFile(RC_DECRYPT)
        }
    }

    fun selectFile(requestCode: Int) {

        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT)

        intent.addCategory(Intent.CATEGORY_OPENABLE)

        intent.type = "*/*"

        startActivityForResult(intent, requestCode)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {

        if (resultCode == Activity.RESULT_OK) when (requestCode) {

            RC_HASH -> {
                try {

                    val fis = context.contentResolver.openInputStream(data?.data)

                    val pDialog = indeterminateProgressDialog("Hashing file...")

                    eCrypt.hash(fis, ECrypt.HashAlgorithms.SHA_256,
                            object : ECrypt.HashResultListener {
                                override fun <T> onHashed(result: T) {
                                    onUiThread {
                                        pDialog.dismiss()
                                        tvResult.text = result as String
                                    }
                                }

                                override fun onFailed(message: String, e: Exception) {
                                    e.printStackTrace()
                                    onUiThread {
                                        pDialog.dismiss()
                                        toast("Error: $message")
                                    }
                                }
                            }, activity)
                } catch (e: FileNotFoundException) {
                    e.printStackTrace()
                    toast("File not found.")
                }
            }

            RC_ENCRYPT -> {
                try {

                    val fis = context.contentResolver.openInputStream(data?.data)
                    val pDialog = indeterminateProgressDialog("Encrypting file...")

                    eCrypt.encrypt(fis, edPassword.text.toString(),
                            object : ECrypt.EncryptionResultListener {
                                override fun <T> onEncrypted(result: T) {
                                    onUiThread {
                                        pDialog.dismiss()
                                        tvResult.text = resources.getString(
                                                R.string.success_file_encrypted,
                                                (result as File).absolutePath)
                                    }
                                }

                                override fun onFailed(message: String, e: Exception) {
                                    e.printStackTrace()
                                    onUiThread {
                                        pDialog.dismiss()
                                        toast("Error: $message")
                                    }
                                }
                            })
                } catch (e: FileNotFoundException) {
                    e.printStackTrace()
                    toast("File not found.")
                }
            }

            RC_DECRYPT -> {
                try {

                    val fis = context.contentResolver.openInputStream(data?.data)
                    val pDialog = indeterminateProgressDialog("Decrypting file...")

                    eCrypt.decrypt(fis, edPassword.text.toString(),
                            object : ECrypt.DecryptionResultListener {
                                override fun <T> onDecrypted(result: T) {
                                    onUiThread {
                                        pDialog.dismiss()
                                        tvResult.text = resources.getString(
                                                R.string.success_file_decrypted,
                                                (result as File).absolutePath)
                                    }
                                }

                                override fun onFailed(message: String, e: Exception) {
                                    e.printStackTrace()
                                    onUiThread {
                                        pDialog.dismiss()
                                        toast("Error: $message")
                                    }
                                }
                            })
                } catch (e: FileNotFoundException) {
                    e.printStackTrace()
                    toast("File not found.")
                }
            }
        }
    }

    companion object {
        fun newInstance(): Fragment = FragmentFile()
    }

}
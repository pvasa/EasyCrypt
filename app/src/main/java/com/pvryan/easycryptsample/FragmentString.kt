package com.pvryan.easycryptsample

import android.os.Bundle
import android.support.annotation.Nullable
import android.support.v4.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import com.pvryan.easycrypt.ECrypt
import kotlinx.android.synthetic.main.fragment_string.*
import org.jetbrains.anko.support.v4.indeterminateProgressDialog
import org.jetbrains.anko.support.v4.onUiThread
import org.jetbrains.anko.support.v4.toast

class FragmentString : Fragment() {

    private val eCrypt = ECrypt()

    override fun onCreateView(inflater: LayoutInflater?, @Nullable container: ViewGroup?,
                              @Nullable savedInstanceState: Bundle?): View? {
        return inflater?.inflate(R.layout.fragment_string, container, false)
    }

    override fun onViewCreated(view: View?, @Nullable savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        buttonEncrypt.setOnClickListener {

            val pDialog = indeterminateProgressDialog("Encrypting...")

            eCrypt.encrypt(edInput.text, edPassword.text.toString(),
                    object : ECrypt.EncryptionResultListener {
                        override fun <T> onEncrypted(result: T) {
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
                    }
            )
        }

        buttonDecrypt.setOnClickListener {

            val pDialog = indeterminateProgressDialog("Decrypting...")

            eCrypt.decrypt(tvResult.text, edPassword.text.toString(),
                    object : ECrypt.DecryptionResultListener {
                        override fun <T> onDecrypted(result: T) {
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

                    }
            )
        }

        buttonHash.setOnClickListener {

            eCrypt.hash(edInput.text, ECrypt.HashAlgorithms.SHA_256,
                    hrl = object : ECrypt.HashResultListener {
                        override fun <T> onHashed(result: T) {
                            onUiThread { tvResult.text = result as String }
                        }

                        override fun onFailed(message: String, e: Exception) {
                            e.printStackTrace()
                            onUiThread { toast("Error: $message") }
                        }
                    },
                    context = activity
            )
        }

    }

    companion object {
        fun newInstance(): Fragment = FragmentString()
    }

}
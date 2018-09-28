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
package com.pvryan.easycryptsample.main

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.Environment
import android.view.Menu
import android.view.MenuItem
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.snackbar.Snackbar
import com.pvryan.easycryptsample.Constants
import com.pvryan.easycryptsample.R
import com.pvryan.easycryptsample.about.AboutActivity
import com.pvryan.easycryptsample.action.ActionActivity
import com.pvryan.easycryptsample.data.models.Card
import com.pvryan.easycryptsample.extensions.checkPermissions
import com.pvryan.easycryptsample.extensions.snackIndefinite
import com.pvryan.easycryptsample.settings.SettingsActivity
import kotlinx.android.synthetic.main.activity_main.mainContent
import kotlinx.android.synthetic.main.activity_main.toolbar
import java.io.File

class MainActivity : AppCompatActivity() {

    private val requiredPermissions = arrayOf(
            Manifest.permission.WRITE_EXTERNAL_STORAGE)

    private var snackbar: Snackbar? = null

    private val outputDir = Environment.getExternalStorageDirectory().absolutePath +
            File.separator + "ECryptSample"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        setSupportActionBar(toolbar)

        val mRecyclerView: RecyclerView = findViewById(R.id.container)
        mRecyclerView.setHasFixedSize(false)
        mRecyclerView.layoutManager = LinearLayoutManager(this)
        mRecyclerView.adapter = MainAdapter(initCards())

        checkPermissions(Constants.rCStoragePermissions, requiredPermissions)
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        // Inflate the menu; this adds items to the action bar if it is present.
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        return when (item.itemId) {
            R.id.action_settings -> {
                val intent = Intent(this, SettingsActivity::class.java)
                intent.putExtra(Constants.TITLE, getString(R.string.title_settings))
                startActivity(intent)
                true
            }
            R.id.action_about -> {
                val intent = Intent(this, AboutActivity::class.java)
                intent.putExtra(Constants.TITLE, getString(R.string.title_about))
                startActivity(intent)
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>,
                                            grantResults: IntArray) {
        when (requestCode) {
            Constants.rCStoragePermissions -> {
                if (grantResults.contains(PackageManager.PERMISSION_DENIED))
                    snackbar = mainContent.snackIndefinite(
                            getString(R.string.text_permissions_required),
                            "Grant", View.OnClickListener {
                        checkPermissions(requestCode, permissions)
                    })
                else {
                    snackbar?.dismiss()
                    File(outputDir).mkdirs()
                }
            }
            else -> super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        }
    }

    private fun getAction(actionType: Int, title: String, subTitle: String): View.OnClickListener {
        val intent = Intent(this, ActionActivity::class.java)
        intent.putExtra(Card.ACTION, actionType)
        intent.putExtra(Constants.TITLE, title)
        intent.putExtra(Constants.SUB_TITLE, subTitle)
        return View.OnClickListener { startActivity(intent) }
    }

    private fun initCards(): ArrayList<Card> = arrayListOf(
            Card("Symmetric-Key Encryption",
                    "Encryption and decryption algorithms " +
                            "both use a same shared key. Very fast, " +
                            "but key sharing is challenging.",
                    "String",
                    "File",
                    action1 = getAction(Card.actionTypeSString,
                            "Symmetric-Key Encryption", "String"),
                    action2 = getAction(Card.actionTypeSFile,
                            "Symmetric-Key Encryption", "File")),
            Card("Asymmetric-Key Encryption",
                    "Encryption is done using a publicly " +
                            "shared part of the key, while decryption requires " +
                            "the other (private) part of the key. Very slow," +
                            " but solves the problem of key sharing.",
                    "String",
                    "File",
                    action1 = getAction(Card.actionTypeAString,
                            "Asymmetric-Key Encryption", "String"),
                    action2 = getAction(Card.actionTypeAFile,
                            "Asymmetric-Key Encryption", "File")),
            Card("Cryptographic Hash function",
                    "A cryptographic hash function is a mathematical" +
                            " algorithm that maps data of arbitrary size" +
                            " to a bit string of a fixed size (a hash)" +
                            " and is designed to be a one-way function," +
                            " that is, a function which is infeasible to invert.",
                    "String",
                    "File",
                    action1 = getAction(Card.actionTypeHString,
                            "Cryptographic Hash function", "String"),
                    action2 = getAction(Card.actionTypeHFile,
                            "Cryptographic Hash function", "File")),
            Card("Password Functions",
                    "Generate secure passwords using pseudo-random" +
                            " or true random generator. Analyze a password" +
                            " for strengths and weaknesses.",
                    "Generate",
                    "Analyze",
                    action1 = getAction(Card.actionTypePGenerate,
                            "Password Functions", "Generate"),
                    action2 = getAction(Card.actionTypePAnalyze,
                            "Password Functions", "Analyze")))
}

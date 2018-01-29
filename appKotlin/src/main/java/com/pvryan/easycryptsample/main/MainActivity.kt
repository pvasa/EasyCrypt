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
package com.pvryan.easycryptsample.main

import android.Manifest
import android.content.Intent
import android.os.Bundle
import android.os.Environment
import android.support.v7.app.AppCompatActivity
import android.support.v7.widget.LinearLayoutManager
import android.support.v7.widget.RecyclerView
import android.view.Menu
import android.view.MenuItem
import android.view.View
import com.pvryan.easycryptsample.R
import com.pvryan.easycryptsample.about.AboutActivity
import com.pvryan.easycryptsample.action.ActionActivity
import com.pvryan.easycryptsample.data.Card
import com.pvryan.easycryptsample.extensions.checkPermissions
import com.pvryan.easycryptsample.extensions.handlePermissionResults
import kotlinx.android.synthetic.main.activity_main.*
import org.jetbrains.anko.toast
import java.io.File

class MainActivity : AppCompatActivity() {

    private val _rCPermissions = 1

    private val outputDir = Environment.getExternalStorageDirectory().absolutePath +
            File.separator + "ECryptSample"

    private fun getAction(actionType: Int, title: String, subTitle: String): View.OnClickListener {
        val intent = Intent(this, ActionActivity::class.java)
        intent.putExtra(Card.ACTION, actionType)
        intent.putExtra(Card.TITLE, title)
        intent.putExtra(Card.SUB_TITLE, subTitle)
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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        setSupportActionBar(toolbar)

        val mRecyclerView: RecyclerView = findViewById(R.id.container)
        mRecyclerView.setHasFixedSize(false)

        val mLayoutManager = LinearLayoutManager(this)
        mRecyclerView.layoutManager = mLayoutManager

        mRecyclerView.adapter = MainAdapter(initCards())
        File(outputDir).mkdirs()
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
                toast("Coming soon")
                true
            }
            R.id.action_about -> {
                val intent = Intent(this, AboutActivity::class.java)
                intent.putExtra(Card.TITLE, getString(R.string.title_about))
                startActivity(intent)
                R.style.about_elementTextAppearance
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    override fun onResume() {
        super.onResume()
        checkPermissions(_rCPermissions,
                Manifest.permission.READ_EXTERNAL_STORAGE,
                Manifest.permission.WRITE_EXTERNAL_STORAGE,
                Manifest.permission.INTERNET)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>,
                                            grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        when (requestCode) {
            _rCPermissions -> handlePermissionResults(requestCode, permissions, grantResults)
        }
    }
}

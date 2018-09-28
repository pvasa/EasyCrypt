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

import android.os.Bundle
import android.view.MenuItem
import androidx.appcompat.app.AppCompatActivity
import com.pvryan.easycryptsample.Constants
import com.pvryan.easycryptsample.R
import com.pvryan.easycryptsample.data.models.Card
import kotlinx.android.synthetic.main.activity_main.toolbar

class ActionActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_action)
        setSupportActionBar(toolbar)

        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = intent.extras?.get(Constants.TITLE) as? String
        supportActionBar?.subtitle = intent.extras?.get(Constants.SUB_TITLE) as? String

        val fragmentTransaction = supportFragmentManager.beginTransaction()
        when (intent.extras?.get(Card.ACTION)) {

            Card.actionTypeSString -> {
                fragmentTransaction.replace(R.id.container, FragmentSymmetricString.newInstance(),
                        FragmentSymmetricString::class.java.simpleName)
            }
            Card.actionTypeSFile -> {
                fragmentTransaction.replace(R.id.container, FragmentSymmetricFile.newInstance(),
                        FragmentSymmetricFile::class.java.simpleName)
            }
            Card.actionTypeAString -> {
                fragmentTransaction.replace(R.id.container, FragmentAsymmetricString.newInstance(),
                        FragmentAsymmetricString::class.java.simpleName)
            }
            Card.actionTypeAFile -> {
                fragmentTransaction.replace(R.id.container, FragmentAsymmetricFile.newInstance(),
                        FragmentAsymmetricFile::class.java.simpleName)
            }
            Card.actionTypeHString -> {
                fragmentTransaction.replace(R.id.container, FragmentHashString.newInstance(),
                        FragmentAsymmetricString::class.java.simpleName)
            }
            Card.actionTypeHFile -> {
                fragmentTransaction.replace(R.id.container, FragmentHashFile.newInstance(),
                        FragmentAsymmetricFile::class.java.simpleName)
            }
            Card.actionTypePGenerate -> {
                fragmentTransaction.replace(R.id.container, FragmentGeneratePassword.newInstance(),
                        FragmentGeneratePassword::class.java.simpleName)
            }
            Card.actionTypePAnalyze -> {
                fragmentTransaction.replace(R.id.container, FragmentAnalyzePassword.newInstance(),
                        FragmentAnalyzePassword::class.java.simpleName)
            }
        }
        fragmentTransaction.commit()
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            android.R.id.home -> {
                super.onBackPressed()
                return true
            }
        }
        return super.onOptionsItemSelected(item)
    }
}

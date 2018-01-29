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
package com.pvryan.easycryptsample.about

import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import android.view.MenuItem
import android.view.View
import com.pvryan.easycryptsample.R
import com.pvryan.easycryptsample.data.Card
import kotlinx.android.synthetic.main.activity_about.*
import mehdi.sakout.aboutpage.AboutPage
import mehdi.sakout.aboutpage.Element


class AboutActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_about)

        setSupportActionBar(toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = intent.extras[Card.TITLE] as String

        val packageInfo = packageManager.getPackageInfo(packageName, 0)
        val appVersionElement = Element()
        appVersionElement.title = "App version ${packageInfo.versionName}"

        val libVersionElement = Element()
        libVersionElement.title = "Library version 1.3.3"

        val view: View = AboutPage(this).isRTL(false)
                .addItem(appVersionElement)
                .addItem(libVersionElement)
                .isRTL(false)
                .setDescription("Secure and efficient cryptography library for Android. (Auto fix SecureRandom bugs in API 18 and below.)")
                .addGroup("Connect with dev")
                .addEmail("priyank.vasa5@gmail.com", "Email")
                .addWebsite("https://ryan652.github.io/", "Know dev")
                .addTwitter("ryanm652", "Follow on Twitter")
                .addGitHub("ryan652/easycrypt", "Source code on GitHub")
                .create()

        container.addView(view)
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

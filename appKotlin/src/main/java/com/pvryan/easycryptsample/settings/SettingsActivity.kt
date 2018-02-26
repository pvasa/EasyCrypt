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
package com.pvryan.easycryptsample.settings

import android.content.SharedPreferences
import android.os.Bundle
import android.preference.Preference
import android.preference.PreferenceFragment
import android.support.v7.app.AppCompatActivity
import android.view.MenuItem
import com.pvryan.easycryptsample.Constants
import com.pvryan.easycryptsample.R
import kotlinx.android.synthetic.main.activity_settings.*
import org.jetbrains.anko.defaultSharedPreferences

class SettingsActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)
        setSupportActionBar(toolbar)

        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = intent.extras[Constants.TITLE] as String

        fragmentManager.beginTransaction().replace(R.id.container, SettingsFragment()).commit()
    }

    class SettingsFragment : PreferenceFragment(),
            SharedPreferences.OnSharedPreferenceChangeListener {

        private lateinit var preference: Preference

        override fun onCreate(savedInstanceState: Bundle?) {
            super.onCreate(savedInstanceState)
            addPreferencesFromResource(R.xml.preferences)

            val prefApiKey = getString(R.string.pref_api_key)
            preference = findPreference(prefApiKey)

            if (!defaultSharedPreferences.getString(prefApiKey, "").isBlank()) {
                preference.summary = getString(R.string.summary_set)
            }
        }

        override fun onPause() {
            super.onPause()
            preferenceScreen.sharedPreferences
                    .unregisterOnSharedPreferenceChangeListener(this@SettingsFragment)
        }

        override fun onResume() {
            super.onResume()
            preferenceScreen.sharedPreferences
                    .registerOnSharedPreferenceChangeListener(this@SettingsFragment)
        }

        override fun onSharedPreferenceChanged(sharedPreferences: SharedPreferences?,
                                               key: String?) {

            when (key) {
                getString(R.string.pref_api_key) -> {
                    val apiKey = defaultSharedPreferences.getString(key, "")
                    if (apiKey.isBlank()) {
                        preference.summary = getString(R.string.summary_not_set)
                    } else {
                        preference.summary = getString(R.string.summary_set)
                    }
                }
            }
        }
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

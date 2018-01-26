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

package com.pvryan.easycryptsample.extensions

import android.content.pm.PackageManager
import android.support.v4.app.ActivityCompat
import android.support.v4.content.ContextCompat
import android.support.v4.util.ArraySet
import android.support.v7.app.AlertDialog
import android.support.v7.app.AppCompatActivity
import com.pvryan.easycryptsample.R

fun AppCompatActivity.checkPermissions(requestCode: Int, vararg permissions: String): Boolean {

    val unGranted = ArraySet<String>()

    permissions.filterTo(unGranted) {
        ContextCompat.checkSelfPermission(this, it) == PackageManager.PERMISSION_DENIED
    }

    if (!unGranted.isEmpty()) {
        ActivityCompat.requestPermissions(
                this, unGranted.toTypedArray<String>(), requestCode)
        return false
    } else {
        return true
    }
}

fun AppCompatActivity.handlePermissionResults(
        requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {

    if (grantResults.contains(PackageManager.PERMISSION_DENIED)) {
        AlertDialog.Builder(this).setCancelable(false)
                .setTitle(getString(R.string.title_permissions))
                .setMessage(getString(R.string.message_permissions))
                .setPositiveButton(getString(R.string.button_grant), {
                    dialog, _ ->
                    checkPermissions(requestCode, *permissions)
                    dialog.dismiss()
                })
                .setNegativeButton(getString(R.string.button_exit), {
                    dialog, _ ->
                    dialog.cancel()
                    finish()
                }).show()
    }

}

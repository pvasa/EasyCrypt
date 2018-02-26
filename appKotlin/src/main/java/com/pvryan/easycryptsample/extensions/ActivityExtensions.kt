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

package com.pvryan.easycryptsample.extensions

import android.content.pm.PackageManager
import android.support.v4.app.ActivityCompat
import android.support.v4.content.ContextCompat
import android.support.v4.util.ArraySet
import android.support.v7.app.AlertDialog
import android.support.v7.app.AppCompatActivity
import com.pvryan.easycryptsample.Constants
import com.pvryan.easycryptsample.R

fun AppCompatActivity.checkPermissions(requestCode: Int, permissions: Array<out String>): Boolean {

    val unGranted = ArraySet<String>()

    permissions.filterTo(unGranted) {
        ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
    }

    return if (unGranted.isEmpty()) {
        true
    } else {
        val message = when (requestCode) {
            Constants.rCStoragePermissions -> getString(R.string.message_storage_permissions)
            Constants.rCCameraPermissions -> getString(R.string.message_camera_permissions)
            else -> getString(R.string.message_general_permissions)
        }
        AlertDialog.Builder(this)
                .setCancelable(true)
                .setTitle(getString(R.string.title_permissions))
                .setMessage(message)
                .setPositiveButton(getString(R.string.button_allow), { dialog, _ ->
                    ActivityCompat.requestPermissions(
                            this, unGranted.toTypedArray(), requestCode)
                    dialog.dismiss()
                })
                .setNegativeButton(getString(R.string.button_deny), { dialog, _ ->
                    dialog.cancel()
                })
                .setOnCancelListener {
                    this.onRequestPermissionsResult(requestCode, permissions,
                            kotlin.intArrayOf(PackageManager.PERMISSION_DENIED))
                }.show()
        false
    }
}

/*fun AppCompatActivity.checkPlayServices() {
    val code = GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(this)
    if (code != ConnectionResult.SUCCESS) {
        GoogleApiAvailability.getInstance()
                .getErrorDialog(this, code, Constants.rCHandleGMS).show()
    }
}*/

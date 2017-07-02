package com.pvryan.easycryptsample.extensions

import android.content.pm.PackageManager
import android.support.v4.app.ActivityCompat
import android.support.v4.content.ContextCompat
import android.support.v4.util.ArraySet
import android.support.v7.app.AlertDialog
import android.support.v7.app.AppCompatActivity

fun AppCompatActivity.checkPermissions(requestCode: Int, vararg permissions: String): Boolean {

    val unGranted = ArraySet<String>()

    permissions.filterTo(unGranted) {
        ContextCompat.checkSelfPermission(this, it) == PackageManager.PERMISSION_DENIED
    }

    if (!unGranted.isEmpty()) {
        ActivityCompat.requestPermissions(this, unGranted.toTypedArray<String>(), requestCode)
        return false
    } else {
        return true
    }
}

fun AppCompatActivity.handlePermissionResults(
        requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {

    if (grantResults.contains(PackageManager.PERMISSION_DENIED)) {
        AlertDialog.Builder(this).setCancelable(false)
                .setTitle("Permissions")
                .setMessage("Permissions required to run this app correctly. " +
                        "Grant to allow or Exit to close the app.")
                .setPositiveButton("Grant", {
                    dialog, _ ->
                    checkPermissions(requestCode, *permissions)
                    dialog.dismiss()
                })
                .setNegativeButton("Exit", {
                    dialog, _ ->
                    dialog.cancel()
                    finish()
                }).show()
    }

}

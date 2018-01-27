package com.pvryan.easycryptsample.extensions

import android.support.design.widget.Snackbar
import android.view.View

private fun View.snack(message: String, length: Int) {
    Snackbar.make(this, message, length).show()
}

fun View.snackShort(message: String) {
    this.snack(message, Snackbar.LENGTH_SHORT)
}

fun View.snackLong(message: String) {
    this.snack(message, Snackbar.LENGTH_LONG)
}

fun View.show() {
    this.visibility = View.VISIBLE
}

fun View.hide() {
    this.visibility = View.INVISIBLE
}

fun View.gone() {
    this.visibility = View.GONE
}

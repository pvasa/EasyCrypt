@file:Suppress("LocalVariableName")

package com.pvryan.easycryptsample.extensions

import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import com.google.android.material.snackbar.Snackbar
import com.google.android.material.textfield.TextInputEditText
import com.transitionseverywhere.TransitionManager

private fun View.snack(
        message: String,
        length: Int,
        actionTitle: String?,
        action: View.OnClickListener?
): Snackbar {
    val snackbar = Snackbar.make(this, message, length)
    if (actionTitle != null && action != null)
        snackbar.setAction(actionTitle, action).show()
    snackbar.show()
    return snackbar
}

fun View.snackShort(
        message: String, actionTitle: String? = null,
        action: View.OnClickListener? = null
) {
    snack(message, Snackbar.LENGTH_SHORT, actionTitle, action)
}

fun View.snackLong(
        message: String, actionTitle: String? = null,
        action: View.OnClickListener? = null
) {
    snack(message, Snackbar.LENGTH_LONG, actionTitle, action)
}

fun View.snackIndefinite(
        message: String,
        actionTitle: String? = null,
        action: View.OnClickListener? = null
): Snackbar = snack(message, Snackbar.LENGTH_INDEFINITE, actionTitle, action)

fun View.show(animate: Boolean = false) {
    if (animate) TransitionManager.beginDelayedTransition(parent as ViewGroup)
    visibility = View.VISIBLE
}

fun View.hide(animate: Boolean = false) {
    if (animate) TransitionManager.beginDelayedTransition(parent as ViewGroup)
    visibility = View.INVISIBLE
}

fun View.gone(animate: Boolean = false) {
    if (animate) TransitionManager.beginDelayedTransition(parent as ViewGroup)
    visibility = View.GONE
}

fun TextInputEditText.setOnClickEndDrawableListener(performAction: () -> Unit) {

    setOnTouchListener(View.OnTouchListener { _, event ->
        //val DRAWABLE_LEFT = 0
        //val DRAWABLE_TOP = 1
        val DRAWABLE_RIGHT = 2
        //val DRAWABLE_BOTTOM = 3

        when (event.action) {
            MotionEvent.ACTION_UP -> if (event.rawX >= (right - compoundDrawables[DRAWABLE_RIGHT].bounds.width())) {
                performAction()
                return@OnTouchListener true
            }
        }
        return@OnTouchListener false
    })
}

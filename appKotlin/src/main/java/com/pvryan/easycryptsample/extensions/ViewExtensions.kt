@file:Suppress("LocalVariableName")

package com.pvryan.easycryptsample.extensions

import android.support.design.widget.Snackbar
import android.support.design.widget.TextInputEditText
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import com.transitionseverywhere.TransitionManager

private fun View.snack(message: String, length: Int,
                       actionTitle: String?, action: View.OnClickListener?): Snackbar {
    val snackbar = Snackbar.make(this, message, length)
    if (actionTitle != null && action != null)
        snackbar.setAction(actionTitle, action).show()
    snackbar.show()
    return snackbar
}

fun View.snackShort(message: String, actionTitle: String? = null,
                    action: View.OnClickListener? = null) {
    this.snack(message, Snackbar.LENGTH_SHORT, actionTitle, action)
}

fun View.snackLong(message: String, actionTitle: String? = null,
                   action: View.OnClickListener? = null) {
    this.snack(message, Snackbar.LENGTH_LONG, actionTitle, action)
}

fun View.snackIndefinite(message: String, actionTitle: String? = null,
                         action: View.OnClickListener? = null): Snackbar = this.snack(message, Snackbar.LENGTH_INDEFINITE, actionTitle, action)

fun View.show(animate: Boolean = false) {
    if (animate) TransitionManager.beginDelayedTransition(parent as ViewGroup)
    this.visibility = View.VISIBLE
}

fun View.hide(animate: Boolean = false) {
    if (animate) TransitionManager.beginDelayedTransition(parent as ViewGroup)
    this.visibility = View.INVISIBLE
}

fun View.gone(animate: Boolean = false) {
    if (animate) TransitionManager.beginDelayedTransition(parent as ViewGroup)
    this.visibility = View.GONE
}

@Suppress("UNUSED_ANONYMOUS_PARAMETER")
fun TextInputEditText.setOnClickEndDrawableListener(performAction: () -> Unit) {
    @Suppress("ClickableViewAccessibility")
    this.setOnTouchListener(View.OnTouchListener { v, event ->
        //val DRAWABLE_LEFT = 0
        //val DRAWABLE_TOP = 1
        val DRAWABLE_RIGHT = 2
        //val DRAWABLE_BOTTOM = 3

        if (event.action == MotionEvent.ACTION_UP) {
            if (event.rawX >= (this.right - this.compoundDrawables[DRAWABLE_RIGHT].bounds.width())) {
                performAction()
                return@OnTouchListener true
            }
        }
        return@OnTouchListener false
    })
}

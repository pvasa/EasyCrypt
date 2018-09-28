package com.pvryan.easycryptsample

import android.content.Context
import android.content.SharedPreferences
import android.preference.PreferenceFragment
import android.preference.PreferenceManager
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment

val AppCompatActivity.defaultPreferences: SharedPreferences get() = PreferenceManager.getDefaultSharedPreferences(this)

fun AppCompatActivity.preferences(name: String): SharedPreferences = getSharedPreferences(name, Context.MODE_PRIVATE)

val Fragment.defaultPreferences: SharedPreferences
    get() = context?.let { PreferenceManager.getDefaultSharedPreferences(it) }
            ?: throw IllegalStateException("Context is null.")

fun Fragment.preferences(name: String): SharedPreferences =
        context?.getSharedPreferences(name, Context.MODE_PRIVATE)
                ?: throw IllegalStateException("Context is null.")

val PreferenceFragment.defaultPreferences: SharedPreferences
    get() = activity?.let { PreferenceManager.getDefaultSharedPreferences(it) }
            ?: throw IllegalStateException("$this is not attached to an activity")

fun PreferenceFragment.preferences(name: String): SharedPreferences =
        activity?.getSharedPreferences(name, Context.MODE_PRIVATE)
                ?: throw IllegalStateException("$this is not attached to an activity")

inline fun SharedPreferences.edit(operation: (SharedPreferences.Editor) -> Unit) {
    edit().apply {
        operation(this)
        apply()
    }
}

/**
 * Puts a key value pair in shared prefs if doesn't exists, otherwise updates value on given [key]
 */
operator fun SharedPreferences.set(key: String, value: Any) {
    when (value) {
        is String -> edit { it.putString(key, value) }
        is Int -> edit { it.putInt(key, value) }
        is Boolean -> edit { it.putBoolean(key, value) }
        is Float -> edit { it.putFloat(key, value) }
        is Long -> edit { it.putLong(key, value) }
        else -> throw UnsupportedOperationException("Cannot set a ${value::class}")
    }
}

/**
 * Finds value on given key.
 * [T] is the type of value
 *
 * @param defaultValue optional default value - will take null for strings,
 * false for bool and -1 for numeric values if [defaultValue] is not specified
 */
inline operator fun <reified T : Any> SharedPreferences.get(
        key: String,
        defaultValue: T? = null
): T = when (T::class) {
    String::class -> getString(key, defaultValue as? String ?: "") as T
    Int::class -> getInt(key, defaultValue as? Int ?: -1) as T
    Boolean::class -> getBoolean(key, defaultValue as? Boolean ?: false) as T
    Float::class -> getFloat(key, defaultValue as? Float ?: -1f) as T
    Long::class -> getLong(key, defaultValue as? Long ?: -1) as T
    else -> throw UnsupportedOperationException("Cannot get a ${T::class}")
}

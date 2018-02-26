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
package com.pvryan.easycryptsample.data.models

import android.view.View

data class Card(val title: String,
                val desc: String,
                val actionText1: String = "Action1",
                val actionText2: String = "Action2",
                val action1: View.OnClickListener? = null,
                val action2: View.OnClickListener? = null) {

    companion object {
        const val ACTION = "action"
        const val actionTypeSString = 2
        const val actionTypeSFile = 3
        const val actionTypeAString = 4
        const val actionTypeAFile = 5
        const val actionTypeHString = 6
        const val actionTypeHFile = 7
        const val actionTypePGenerate = 8
        const val actionTypePAnalyze = 9
    }
}

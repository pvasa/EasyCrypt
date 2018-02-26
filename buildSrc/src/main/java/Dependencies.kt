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
@Suppress("unused")
internal object Dependencies {

    const val kotlinStdlib = "org.jetbrains.kotlin:kotlin-stdlib:${Versions.kotlin}"
    const val anko = "org.jetbrains.anko:anko:${Versions.anko}"
    const val ankoCommons = "org.jetbrains.anko:anko-commons:${Versions.anko}"

    const val retrofit = "com.squareup.retrofit2:retrofit:${Versions.retrofit}"
    const val converterGson = "com.squareup.retrofit2:converter-gson:${Versions.retrofit}"
    const val zxcvbn = "com.nulab-inc:zxcvbn:${Versions.zxcvbn}"

    const val supportV4 = "com.android.support:support-v4:${Versions.support}"
    const val cardviewV7 = "com.android.support:cardview-v7:${Versions.support}"
    const val recyclerviewV7 = "com.android.support:recyclerview-v7:${Versions.support}"
    const val appcompatV7 = "com.android.support:appcompat-v7:${Versions.support}"
    const val supportDesign = "com.android.support:design:${Versions.support}"
    const val transitionsEverywhere = "com.andkulikov:transitionseverywhere:${Versions.transitionsEverywhere}"
    const val cameraview = "com.github.google:cameraview:3eaeac0"
    const val aboutPage = "com.github.medyo:android-about-page:${Versions.aboutPage}"
    const val easycrypt = "com.pvryan.easycrypt:easycrypt:${Versions.easyCrypt}"

}

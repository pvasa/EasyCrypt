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
package com.pvryan.easycrypt.symmetric

/**
 * Passwords can have one of these strengths
 */
enum class ECPasswordStrengths(val value: Int) {
    STRENGTH_VERY_WEAK(0),
    STRENGTH_WEAK(1),
    STRENGTH_AVERAGE(2),
    STRENGTH_STRONG(3),
    STRENGTH_VERY_STRONG(4)
}

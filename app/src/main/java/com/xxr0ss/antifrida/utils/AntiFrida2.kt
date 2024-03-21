package com.xxr0ss.antifrida.utils

class AntiFrida2 {
    external fun checkBeingDebugged(): Boolean

    init {
        System.loadLibrary("native-lib")
    }
}
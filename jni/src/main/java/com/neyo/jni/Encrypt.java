package com.neyo.jni;

/**
 * Created by Neyo on 2017/8/3.
 */

public class Encrypt {

    static {
        System.loadLibrary("encrypt");
    }

    public static native String encode(Object context, String str);
}

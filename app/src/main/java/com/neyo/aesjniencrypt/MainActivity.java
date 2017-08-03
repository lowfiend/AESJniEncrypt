package com.neyo.aesjniencrypt;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import com.neyo.jni.Encrypt;


public class MainActivity extends AppCompatActivity {

    private final static String KeyAES = "1234567890123456";
    private final static String TextAES = "Neyo AES/CBC/PKCS5Padding";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        try {
            Log.e("Neyo-JNIEncrypt", Encrypt.encode(this, TextAES));

            Log.e("Neyo-en", AESUtil.Encrypt(TextAES, KeyAES));
            Log.e("Neyo-de", AESUtil.Decrypt(AESUtil.Encrypt(TextAES, KeyAES), KeyAES));
        } catch (Exception e) {
            Log.e("Neyo", e.toString());
        }

    }
}

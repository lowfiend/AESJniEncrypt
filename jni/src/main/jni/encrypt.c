//
// Created by Neyo on 2017/8/3.
//

#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <android/log.h>

#define   LOG_TAG  "Neyo"
# define NELEM(x) ((int) (sizeof(x) / sizeof((x)[0])))
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define JNIREG_CLASS "com/neyo/jni/Encrypt"

const char *encKey = "1234567890123456";
const char base[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

char *base64_encode(const char *data, int data_len);

__attribute__((section (".mytext")))
JNIEXPORT jstring JNICALL encode(JNIEnv *env, jobject instance, jobject context, jstring source) {

    const char *result = (*env)->GetStringUTFChars(env, source, 0);

    jclass strClass = (*env)->FindClass(env, "java/lang/String");
    jmethodID ctorID = (*env)->GetMethodID(env, strClass, "<init>", "([BLjava/lang/String;)V");
    jbyteArray bytes = (*env)->NewByteArray(env, strlen(encKey));
    (*env)->SetByteArrayRegion(env, bytes, 0, strlen(encKey), (jbyte *) encKey);
    jstring encoding = (*env)->NewStringUTF(env, "utf-8");
    jstring key = (jstring) (*env)->NewObject(env, strClass, ctorID, bytes, encoding);
    jmethodID mid = (*env)->GetMethodID(env, strClass, "getBytes", "(Ljava/lang/String;)[B");
    jbyteArray keyArray = (jbyteArray) (*env)->CallObjectMethod(env, key, mid, encoding);

    jbyteArray dataBytes = (*env)->NewByteArray(env, strlen(result));
    (*env)->SetByteArrayRegion(env, dataBytes, 0, strlen(result), (jbyte *) result);
    jstring data = (jstring) (*env)->NewObject(env, strClass, ctorID, dataBytes, encoding);
    jbyteArray dataArray = (jbyteArray) (*env)->CallObjectMethod(env, data, mid, encoding);

    jclass cls_SecretKeySpe = (*env)->FindClass(env, "javax/crypto/spec/SecretKeySpec");
    jmethodID constructor_SecretKeySpe = (*env)->GetMethodID(env, cls_SecretKeySpe, "<init>",
                                                             "([BLjava/lang/String;)V");
    jobject myKey = NULL;
    myKey = (*env)->NewObject(env, cls_SecretKeySpe, constructor_SecretKeySpe, keyArray,
                              (*env)->NewStringUTF(env, "AES"));
    jclass cls_IvParameterSpec = (*env)->FindClass(env, "javax/crypto/spec/IvParameterSpec");
    jmethodID constructor_IvParameterSpec = (*env)->GetMethodID(env, cls_IvParameterSpec, "<init>",
                                                                "([B)V");
    jobject ivspec = NULL;
    ivspec = (*env)->NewObject(env, cls_IvParameterSpec, constructor_IvParameterSpec, keyArray);

    jclass cls_Cipher = (*env)->FindClass(env, "javax/crypto/Cipher");
    jfieldID fid = (*env)->GetStaticFieldID(env, cls_Cipher, "ENCRYPT_MODE", "I");
    jint cipher_mode = (*env)->GetStaticIntField(env, cls_Cipher, fid);
    jmethodID mid_getInstance = (*env)->GetStaticMethodID(env, cls_Cipher, "getInstance",
                                                          "(Ljava/lang/String;)Ljavax/crypto/Cipher;");
    jobject obj_Cipher = (*env)->CallStaticObjectMethod(env, cls_Cipher, mid_getInstance,
                                                        (*env)->NewStringUTF(env,
                                                                             "AES/CBC/PKCS5Padding"));

    jclass cls_Cipher_init = (*env)->GetObjectClass(env, obj_Cipher);
    jmethodID mid_init = (*env)->GetMethodID(env, cls_Cipher_init, "init",
                                             "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V");
    (*env)->CallVoidMethod(env, obj_Cipher, mid_init, cipher_mode, myKey, ivspec);
    jmethodID mid_doFinal = (*env)->GetMethodID(env, cls_Cipher_init, "doFinal", "([B)[B");
    jbyteArray ecrypted_data = (jbyteArray) (*env)->CallObjectMethod(env, obj_Cipher, mid_doFinal,
                                                                     dataArray);

    //release object
    (*env)->DeleteLocalRef(env, myKey);
    (*env)->DeleteLocalRef(env, ivspec);
    (*env)->DeleteLocalRef(env, obj_Cipher);

    //release string
    (*env)->DeleteLocalRef(env, encoding);
    (*env)->DeleteLocalRef(env, key);
    (*env)->DeleteLocalRef(env, data);
    //release class
    (*env)->DeleteLocalRef(env, strClass);
    (*env)->DeleteLocalRef(env, cls_SecretKeySpe);
    (*env)->DeleteLocalRef(env, cls_IvParameterSpec);
    (*env)->DeleteLocalRef(env, cls_Cipher);
    (*env)->DeleteLocalRef(env, cls_Cipher_init);

    char *t = 0;

    jsize alen = (*env)->GetArrayLength(env, ecrypted_data);
    jbyte *ba = (*env)->GetByteArrayElements(env, ecrypted_data, JNI_FALSE);
    if (alen > 0) {
        t = (char *) malloc(alen + 1);
        memcpy(t, ba, alen);
        t[alen] = 0;
    }
    (*env)->ReleaseByteArrayElements(env, ecrypted_data, ba, 0);

    char *enc = base64_encode(t, alen);

    return (*env)->NewStringUTF(env, enc);
}

static JNINativeMethod method_table[] = {
        {"encode", "(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;", (void *) encode}
};


static int registerNativeMethods(JNIEnv *env, const char *className, JNINativeMethod *gMethods,
                                 int numMethods) {
    jclass clazz;
    clazz = (*env)->FindClass(env, className);
    if (clazz == NULL) {
        return JNI_FALSE;
    }
    if ((*env)->RegisterNatives(env, clazz, gMethods, numMethods) < 0) {
        return JNI_FALSE;
    }

    return JNI_TRUE;
}

int register_ndk_load(JNIEnv *env) {
    return registerNativeMethods(env, JNIREG_CLASS, method_table, NELEM(method_table));
}

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    jint result = -1;

    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_4) != JNI_OK) {
        return result;
    }

    register_ndk_load(env);


    return JNI_VERSION_1_4;
}

char *base64_encode(const char *data, int data_len) {
    //int data_len = strlen(data);
    int prepare = 0;
    int ret_len;
    int temp = 0;
    char *ret = NULL;
    char *f = NULL;
    int tmp = 0;
    char changed[4];
    int i = 0;
    ret_len = data_len / 3;
    temp = data_len % 3;
    if (temp > 0) {
        ret_len += 1;
    }
    ret_len = ret_len * 4 + 1;
    ret = (char *) malloc(ret_len);

    if (ret == NULL) {
        LOGE("No enough memory.\n");
    }
    memset(ret, 0, ret_len);
    f = ret;
    while (tmp < data_len) {
        temp = 0;
        prepare = 0;
        memset(changed, '\0', 4);
        while (temp < 3) {
            //printf("tmp = %d\n", tmp);
            if (tmp >= data_len) {
                break;
            }
            prepare = ((prepare << 8) | (data[tmp] & 0xFF));
            tmp++;
            temp++;
        }
        prepare = (prepare << ((3 - temp) * 8));
        //printf("before for : temp = %d, prepare = %d\n", temp, prepare);
        for (i = 0; i < 4; i++) {
            if (temp < i) {
                changed[i] = 0x40;
            } else {
                changed[i] = (prepare >> ((3 - i) * 6)) & 0x3F;
            }
            *f = base[changed[i]];
            //printf("%.2X", changed[i]);
            f++;
        }
    }
    *f = '\0';

    return ret;

}

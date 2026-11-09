#pragma once

#include <cstdint>

using jint = int32_t;
using jlong = int64_t;
using jboolean = uint8_t;
using jstring = const char *;
using jintArray = void *;
using jobjectArray = void *;
struct JNINativeMethod;

struct JNIEnv;
struct JNINativeInterface_ {
    const char *(*GetStringUTFChars)(JNIEnv *, jstring, jboolean *);
    void (*ReleaseStringUTFChars)(JNIEnv *, jstring, const char *);
};

struct JNIEnv {
    const JNINativeInterface_ *functions;
    const char *GetStringUTFChars(jstring string, jboolean *copy) {
        return functions->GetStringUTFChars(this, string, copy);
    }
    void ReleaseStringUTFChars(jstring string, const char *characters) {
        functions->ReleaseStringUTFChars(this, string, characters);
    }
};

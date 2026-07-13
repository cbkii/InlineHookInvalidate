LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := inlinehookinvalidate
LOCAL_C_INCLUDES := $(LOCAL_PATH)/xdl
LOCAL_SRC_FILES := main.cpp xdl/xdl.c xdl/xdl_iterate.c xdl/xdl_linker.c xdl/xdl_lzma.c xdl/xdl_util.c
LOCAL_LDLIBS := -llog -ldl
include $(BUILD_SHARED_LIBRARY)

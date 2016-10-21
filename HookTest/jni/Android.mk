LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_LDLIBS    := -llog
LOCAL_MODULE    := inject
LOCAL_SRC_FILES := inject.c

#include $(BUILD_EXECUTABLE)
include $(BUILD_SHARED_LIBRARY)
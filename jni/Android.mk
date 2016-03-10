# A simple test for the minimal standard C++ library
#

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := ssh
LOCAL_SRC_FILES := ssh.c
include $(BUILD_EXECUTABLE)

/* Internal C11/MSVC thread-local storage for static-duration data only. */
#ifndef AX_THREAD_LOCAL_H
#define AX_THREAD_LOCAL_H
#if defined(_MSC_VER)
#define AX_THREAD_LOCAL __declspec(thread)
#else
#define AX_THREAD_LOCAL _Thread_local
#endif
#endif

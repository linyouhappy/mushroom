#ifndef __mr_log_h__
#define __mr_log_h__

#include <stdio.h>
#include <string.h>
#include "mr_time.h"

#if _MSC_VER
// #define snprintf _snprintf
#endif



#if (!defined(__STDC__))

#define MRLOG(__FORMAT__, ...) do{\
	char log_buf[256] = {0};\
	snprintf(log_buf, sizeof(log_buf), __FORMAT__, ##__VA_ARGS__);\
	fprintf(stderr, "%s:%d[%s]%lld::%s",__FILE__, __LINE__, "LOG", mr_time(), log_buf);\
}while(0)

#define MRDEBUG(__FORMAT__, ...) do{\
	char log_buf[256] = {0};\
	snprintf(log_buf, sizeof(log_buf), __FORMAT__, ##__VA_ARGS__);\
	fprintf(stderr, "%s:%d[%s]%lld::%s",__FILE__, __LINE__, "DEBUG", mr_time(), log_buf);\
}while(0)

#define MRWARN(__FORMAT__, ...) do{\
	char log_buf[256] = {0};\
	snprintf(log_buf, sizeof(log_buf), __FORMAT__, ##__VA_ARGS__);\
	fprintf(stderr, "%s:%d[%s]%lld::%s",__FILE__, __LINE__, "WARN", mr_time(), log_buf);\
}while(0)

#define MRERROR(__FORMAT__, ...) do{\
	char log_buf[256] = {0};\
	snprintf(log_buf, sizeof(log_buf), __FORMAT__, ##__VA_ARGS__);\
	fprintf(stderr, "%s:%d[%s]%lld::%s",__FILE__, __LINE__, "ERROR", mr_time(), log_buf);\
}while(0)

// #elif defined(__STDC_VERSION__)
#else

#define MRLOG(__FORMAT__, __VA_ARG__...) do{\
	char log_buf[256] = {0};\
	snprintf(log_buf, sizeof(log_buf), __FORMAT__, ##__VA_ARG__);\
	fprintf(stderr, "%s:%d[%s]%lld::%s",__FILE__, __LINE__, "LOG", mr_time(), log_buf);\
}while(0)

#define MRDEBUG(__FORMAT__, __VA_ARG__...) do{\
	char log_buf[256] = {0};\
	snprintf(log_buf, sizeof(log_buf), __FORMAT__, ##__VA_ARG__);\
	fprintf(stderr, "%s:%d[%s]%lld::%s",__FILE__, __LINE__, "DEBUG", mr_time(), log_buf);\
}while(0)

#define MRWARN(__FORMAT__, __VA_ARG__...) do{\
	char log_buf[256] = {0};\
	snprintf(log_buf, sizeof(log_buf), __FORMAT__, ##__VA_ARG__);\
	fprintf(stderr, "%s:%d[%s]%lld::%s",__FILE__, __LINE__, "WARN", mr_time(), log_buf);\
}while(0)

#define MRERROR(__FORMAT__, __VA_ARG__...) do{\
	char log_buf[256] = {0};\
	snprintf(log_buf, sizeof(log_buf), __FORMAT__, ##__VA_ARG__);\
	fprintf(stderr, "%s:%d[%s]%lld::%s",__FILE__, __LINE__, "ERROR", mr_time(), log_buf);\
}while(0)

// #define MRLOG(__FORMAT__, __VA_ARG__...) LOG_BODY("LOG", __FORMAT__, "##__VA_ARG__")
// #define MRDEBUG(__FORMAT__, __VA_ARG__...) LOG_BODY("EBUG", __FORMAT__, "##__VA_ARG__")
// #define MRWARN(__FORMAT__, __VA_ARG__...) LOG_BODY("WARN", __FORMAT__, "##__VA_ARG__")
// #define MRERROR(__FORMAT__, __VA_ARG__...) LOG_BODY("ERROR", __FORMAT__, "##__VA_ARG__")

#endif



#endif



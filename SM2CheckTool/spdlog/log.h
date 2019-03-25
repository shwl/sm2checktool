#ifndef _LOG_H_
#define _LOG_H_

enum TG_LOG_LEVEL
{
	_LOG_DEBUG,
	_LOG_INFO,
	_LOG_WARN,
	_LOG_ERROR,
};

void  TG_WriteLog(TG_LOG_LEVEL level, const char* fmt, ...);
void  TG_WriteLog(TG_LOG_LEVEL level, const wchar_t* fmt, ...);

#define MODEL_INFO "<%s [%d] - %s> <"
#define LOG_DEBUG(fmt, ...)		TG_WriteLog(TG_LOG_LEVEL::_LOG_DEBUG, MODEL_INFO#fmt">" , __FILE__, __LINE__, __FUNCTION__,  ##__VA_ARGS__)
#define LOG_INFO(fmt, ... )		TG_WriteLog(TG_LOG_LEVEL::_LOG_INFO, MODEL_INFO#fmt">" , __FILE__, __LINE__, __FUNCTION__,  ##__VA_ARGS__)
#define LOG_WARN(fmt, ... )		TG_WriteLog(TG_LOG_LEVEL::_LOG_WARN, MODEL_INFO#fmt">" , __FILE__, __LINE__, __FUNCTION__,  ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...)		TG_WriteLog(TG_LOG_LEVEL::_LOG_ERROR, MODEL_INFO#fmt">" , __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#define LOG_LOCATE				TG_WriteLog(TG_LOG_LEVEL::_LOG_INFO, "File:%s,Line:%d,Function:%s", __FILE__, __LINE__, __FUNCTION__)

#define LOGW_DEBUG(fmt, ...)	TG_WriteLog(TG_LOG_LEVEL::_LOG_DEBUG, fmt,  ##__VA_ARGS__)
#define LOGW_INFO(fmt, ... )	TG_WriteLog(TG_LOG_LEVEL::_LOG_INFO, fmt,  ##__VA_ARGS__)
#define LOGW_WARN(fmt, ... )	TG_WriteLog(TG_LOG_LEVEL::_LOG_WARN, fmt,  ##__VA_ARGS__)
#define LOGW_ERROR(fmt, ...)	TG_WriteLog(TG_LOG_LEVEL::_LOG_ERROR, fmt, ##__VA_ARGS__)
#endif

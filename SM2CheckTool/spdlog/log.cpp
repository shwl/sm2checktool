#if defined( _MSC_VER )
#if !defined( _CRT_SECURE_NO_WARNINGS )
#define _CRT_SECURE_NO_WARNINGS		// This test file is not intended to be secure.
#endif
#endif

#include "log.h"
#include <stdio.h>
#include <memory>
#include <time.h>
#include <WinSock2.h>
#include <stdarg.h>
#include <comutil.h>
#pragma comment(lib, "comsuppw.lib")

#include "spdlog/spdlog.h"
#include "spdlog/fmt/ostr.h"
#include "spdlog/common.h"
namespace spd = spdlog;

#define LOG_CFG_FILE							"tglog.ini"
#define LOG_SECTION								"tglog"
#define LOG_LOGGER_NAME							"tglog"
#define LOG_KEY_FILENAME						"logfilename"
#define LOG_KEY_MAX_FILE_SIZE					"max_file_size"
#define	LOG_KEY_MAX_FILE_NUM					"max_file_num"
#define LOG_KEY_LOG_LEVEL						"loglevel"
#define LOG_KEY_FRUSH_LEVEL						"frushlevel"
#define LOG_KEY_TIME_STATISTIC					"timestatistic"
#define LOG_KEY_TIME_INTERVAL					"timeinterval"

#define LOG_DEFAULT_FILENAME					"tg_sm2check.log"
#define LOG_DEFAULT_TIME_STATISCTIC_FILENAME	"tg_timestatistic_sm2check.log"
#define LOG_DEFAULT_MAX_FILE_SIZE				1024 * 1024 * 10
#define LOG_DEFAULT_MAX_FILE_NUM				3
#ifdef _DEBUG
#define LOG_DEFAULT_LOG_LEVEL					spd::level::debug
#define LOG_DEFAULT_FRUSH_LEVEL					spd::level::debug
#else
#define LOG_DEFAULT_LOG_LEVEL					spd::level::err
#define LOG_DEFAULT_FRUSH_LEVEL					spd::level::err
#endif

#define LOG_DEFAULT_TIME_STATISTIC				0
#define LOG_DEFAULT_TIME_INTERVAL				100

static std::shared_ptr<spdlog::logger> g_spdLogger = NULL;
static std::shared_ptr<spdlog::logger> g_spdTimeStatisticLogger = NULL;
static float timestatistic_interval = 0.1f;    //时间统计间隔，超过该时间统计，单位:秒;
struct log_timestatistic
{
	timeval _time;
	int _line;
};

static int gettimeofday(struct timeval *tp)
{
    time_t clock;
    struct tm tm;
    SYSTEMTIME wtm;
    GetLocalTime(&wtm);
    tm.tm_year   = wtm.wYear - 1900;
    tm.tm_mon   = wtm.wMonth - 1;
    tm.tm_mday   = wtm.wDay;
    tm.tm_hour   = wtm.wHour;
    tm.tm_min   = wtm.wMinute;
    tm.tm_sec   = wtm.wSecond;
    tm. tm_isdst  = -1;
    clock = mktime(&tm);
    tp->tv_sec = clock;
    tp->tv_usec = wtm.wMilliseconds * 1000;

    return 0;
}

void InitLogProperites()
{
	if (g_spdLogger != NULL) {
		return;
	}

	std::string logCfgFile = LOG_CFG_FILE;

    char buf[1024] = { 0 };
	long bufLen = _countof(buf);

	//日志输出文件;
	char szPath[MAX_PATH] = {};
	GetTempPathA(MAX_PATH, szPath);
	std::string tmpPath = szPath;
	GetPrivateProfileStringA(LOG_SECTION, LOG_KEY_FILENAME, LOG_DEFAULT_FILENAME, buf, bufLen, logCfgFile.c_str());
	std::string logFileName = tmpPath;
	logFileName.append(buf);
	
	//单个文件大小;
	unsigned long logMaxFileSize = GetPrivateProfileIntA(LOG_SECTION,
		LOG_KEY_MAX_FILE_SIZE, LOG_DEFAULT_MAX_FILE_SIZE, logCfgFile.c_str());
	
	//最多日志文件个数;
	unsigned long logMaxFileNum = GetPrivateProfileIntA(LOG_SECTION,
		LOG_KEY_MAX_FILE_NUM, LOG_DEFAULT_MAX_FILE_NUM, logCfgFile.c_str());
	
	//日志输出级别;
	spd::level::level_enum logLevel = (spd::level::level_enum)GetPrivateProfileIntA(LOG_SECTION,
		LOG_KEY_LOG_LEVEL, LOG_DEFAULT_LOG_LEVEL, logCfgFile.c_str());

	//异步日志写入级别;
	spd::level::level_enum frushLevel = (spd::level::level_enum)GetPrivateProfileIntA(LOG_SECTION,
		LOG_KEY_FRUSH_LEVEL, LOG_DEFAULT_FRUSH_LEVEL, logCfgFile.c_str());
	
	spd::set_level(logLevel);
	g_spdLogger = spd::rotating_logger_mt(LOG_LOGGER_NAME, logFileName.c_str(), logMaxFileSize, logMaxFileNum);
	if (g_spdLogger != NULL) {
		g_spdLogger->flush_on(frushLevel); //日志异步写入,此处设置高于或等于该等级日志时立即刷新;
		g_spdLogger->info(logCfgFile.c_str());
	}
   
	int timeStatistic = GetPrivateProfileIntA(LOG_SECTION, LOG_KEY_TIME_STATISTIC, LOG_DEFAULT_TIME_STATISTIC, logCfgFile.c_str());
    if(0 != timeStatistic)
	{
		float fTmp = GetPrivateProfileIntA(LOG_SECTION, LOG_KEY_TIME_INTERVAL, LOG_DEFAULT_TIME_INTERVAL, logCfgFile.c_str());
        timestatistic_interval = fTmp * 0.001f;
		std::string logTimeFileName = tmpPath + LOG_DEFAULT_TIME_STATISCTIC_FILENAME;
		g_spdTimeStatisticLogger = spd::rotating_logger_mt(LOG_LOGGER_NAME, logTimeFileName.c_str(), logMaxFileSize, logMaxFileNum);
		if (g_spdTimeStatisticLogger != NULL) {
			g_spdTimeStatisticLogger->flush_on(spd::level::level_enum::debug);
		}
    }
}

static void TG_WriteLog_Real(const TG_LOG_LEVEL tglevel, const char* pLogInfo)
{
    switch (tglevel)
    {
    case _LOG_ERROR:
        g_spdLogger->error(pLogInfo);
        break;
	case _LOG_WARN:
        g_spdLogger->warn(pLogInfo);
		break;
    case _LOG_INFO:
        g_spdLogger->info(pLogInfo);
        break;
	default:
        g_spdLogger->debug(pLogInfo);
		break;
    }
}

void TG_WriteLog(TG_LOG_LEVEL level, const char* fmt, ...)
{
    if(NULL == g_spdLogger) {
        InitLogProperites();
    }

    if(NULL == g_spdLogger) {
        return;
    }

    char* pBuf = NULL;
    try {
        va_list argptr;          //分析字符串的格式;
        va_start(argptr, fmt);
        const int bufLen = vsnprintf(NULL, 0, fmt, argptr) + 1;
        va_end(argptr);
		if (0 >= bufLen){
			throw "0 >= bufLen";
		}
        va_start(argptr, fmt);
        pBuf = new char[bufLen];
        memset(pBuf, 0, bufLen);
		vsprintf_s(pBuf, bufLen, fmt, argptr);
        va_end(argptr);

        std::string strFmt = fmt;
        static std::map<std::string, log_timestatistic> func_name_time_map;   //函数名称及调用时间历史记录;
        if(g_spdTimeStatisticLogger && std::string::npos != strFmt.find(MODEL_INFO))
        {
            va_start(argptr, fmt);

            std::string cppName = va_arg(argptr, char*);
            int line = va_arg(argptr, int);
            std::string funcname = va_arg(argptr, char*);
            auto it = func_name_time_map.find(funcname);
            if(it != func_name_time_map.end())
            {
                bool bFlag = false;
                if(it->second._line < line){
                    bFlag = true;
                }
                timeval curTime;
                gettimeofday(&curTime);
                float timeInterval = 0;
                if(bFlag){
                    timeInterval = (curTime.tv_sec - it->second._time.tv_sec) + float(curTime.tv_usec - it->second._time.tv_usec) / 1000000;
                }
                it->second._time = curTime;
                it->second._line = line;
                if(bFlag && timestatistic_interval < timeInterval)
                {
                    char* pData = new char[bufLen + 32];
                    sprintf(pData, "TimeInterval:%.04fs, funcName:%s, cppName:%s, line:%d",timeInterval, funcname.c_str(), cppName.c_str(), line);
                    g_spdTimeStatisticLogger->debug(pData);
					delete[] pData;
                }
            }
            else
            {
                timeval curTime;
                gettimeofday(&curTime);
                log_timestatistic lt;
                lt._time = curTime;
                lt._line = line;
                func_name_time_map.insert(make_pair(funcname, lt));
            }
            va_end(argptr);
        }
    }
    catch (...) {
    }

    if (pBuf != NULL)
	{
		TG_WriteLog_Real(level, pBuf);
		delete[] pBuf;
		pBuf = NULL;
    }
}

void TG_WriteLog(TG_LOG_LEVEL level, const wchar_t* fmt, ...)
{
	try
	{
		va_list argptr;          //分析字符串的格式;
		va_start(argptr, fmt);
		const int bufLen = _vsnwprintf(NULL, 0, fmt, argptr) + 1;
		va_end(argptr);
		if (0 < bufLen)
		{
			va_start(argptr, fmt);
			wchar_t* pBuf = new wchar_t[bufLen];
			wmemset(pBuf, 0, bufLen);
			vswprintf_s(pBuf, bufLen, fmt, argptr);
			va_end(argptr);
			char *pData = _com_util::ConvertBSTRToString(pBuf);
			TG_WriteLog(level, pData);
			delete[] pData;
			delete[] pBuf;
		}
	}
	catch (...)
	{
	}
}

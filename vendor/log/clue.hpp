// Copyright 2014, 2021 by Martin Moene
//
// clue is based on ideas by Mark Nelson, see article at
// http://www.drdobbs.com/cpp/blundering-into-the-one-definition-rule/240166489
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#ifndef CLUE_CLUE_H_INCLUDED
#define CLUE_CLUE_H_INCLUDED

#define clue_MAJOR  1
#define clue_MINOR  0
#define clue_PATCH  0

#define clue_VERSION  clue_STRINGIFY(clue_MAJOR) "." clue_STRINGIFY(clue_MINOR) "." clue_STRINGIFY(clue_PATCH)

#define clue_STRINGIFY(  x )  clue_STRINGIFY_( x )
#define clue_STRINGIFY_( x )  #x

#include <iomanip>
#include <sstream>
#include <cassert>

#if defined( _MSC_VER )
# define clue_COMPILER_IS_MSVC
# if ( _MSC_VER >= 1200 ) && ( _MSC_VER < 1300 )
#  define clue_COMPILER_IS_MSVC6
# endif
#endif

#ifdef clue_COMPILER_IS_MSVC
# pragma warning( push )
# pragma warning( disable : 4996 ) // _CRT_SECURE_NO_WARNINGS
#endif

#ifndef clue_NO_SHORT_NAMES

# ifdef  LOG_MODULE_NAME
#  define clue_LOG_MODULE_NAME  LOG_MODULE_NAME
# endif

# ifdef  LOG_LEVEL
#  define clue_LOG_LEVEL        LOG_LEVEL
# endif

# ifdef  LOG_LEVEL_BUILD
#  define clue_LOG_LEVEL_BUILD  LOG_LEVEL_BUILD
# endif

# ifdef  LOG_TO_CONSOLE
#  define clue_LOG_TO_CONSOLE   LOG_TO_CONSOLE
# endif

# ifdef  LOG_TO_FILE
#  define clue_LOG_TO_FILE      LOG_TO_FILE
# endif

# ifdef  LOG_TO_DEBUGGER
#  define clue_LOG_TO_DEBUGGER  LOG_TO_DEBUGGER
# endif

# ifdef  LOG_TO_DEBUGGER_WINDOWS
#  define clue_LOG_TO_DEBUGGER_WINDOWS  LOG_TO_DEBUGGER_WINDOWS
# endif

# ifdef  LOG_TO_EVENTLOG
#  define clue_LOG_TO_EVENTLOG  LOG_TO_EVENTLOG
# endif

# ifdef  LOG_TO_STRING
#  define clue_LOG_TO_STRING    LOG_TO_STRING
# endif

# ifdef  LOG_TO_SYSLOG
#  define clue_LOG_TO_SYSLOG    LOG_TO_SYSLOG
# endif

# ifdef  LOG_EXPRESSION
#  define clue_LOG_EXPRESSION   LOG_EXPRESSIONLOG_TO_SYSLOG
# endif

#endif // clue_NO_SHORT_NAMES

// now we can determine if we must guess a destination:

#ifndef clue_OMIT_UNUSED_LOG_EXPRESSION
# define clue_OMIT_UNUSED_LOG_EXPRESSION 0
#endif


#if !defined( clue_LOG_TO_CONSOLE  ) && \
    !defined( clue_LOG_TO_FILE     ) && \
    !defined( clue_LOG_TO_STRING   ) && \
    !defined( clue_LOG_TO_DEBUGGER ) && \
    !defined( clue_LOG_TO_EVENTLOG ) && \
    !defined( clue_LOG_TO_SYSLOG   )
# if defined( _WINDOWS )
#  define clue_LOG_TO_DEBUGGER
#elif defined( NTS_TO_BE_DETERMINED_UNIX )
#  define clue_LOG_TO_SYSLOG
# else
#  define clue_LOG_TO_CONSOLE
# endif
#endif

#if defined( clue_LOG_TO_CONSOLE  ) + \
    defined( clue_LOG_TO_FILE     ) + \
    defined( clue_LOG_TO_STRING   ) + \
    defined( clue_LOG_TO_DEBUGGER ) + \
    defined( clue_LOG_TO_EVENTLOG ) + \
    defined( clue_LOG_TO_SYSLOG   ) > 1
# error Please specify one, or none of [clue_]LOG_TO_CONSOLE, [clue_]LOG_TO_FILE, [clue_]LOG_TO_STRING, [clue_]LOG_TO_DEBUGGER [clue_]LOG_TO_EVENTLOG and [clue_]LOG_TO_SYSLOG
#endif

// NTS: add UNIX
#ifdef clue_LOG_TO_DEBUGGER
# define clue_LOG_TO_DEBUGGER_WINDOWS
#endif

#ifndef clue_NO_SHORT_NAMES

# define LOG_SEV_NONE       clue_LOG_SEV_NONE
# define LOG_SEV_EMERGENCY  clue_LOG_SEV_EMERGENCY
# define LOG_SEV_ALERT      clue_LOG_SEV_ALERT
# define LOG_SEV_CRITICAL   clue_LOG_SEV_CRITICAL
# define LOG_SEV_ERROR      clue_LOG_SEV_ERROR
# define LOG_SEV_WARNING    clue_LOG_SEV_WARNING
# define LOG_SEV_NOTICE     clue_LOG_SEV_NOTICE
# define LOG_SEV_INFO       clue_LOG_SEV_INFO
# define LOG_SEV_DEBUG      clue_LOG_SEV_DEBUG
# define LOG_SEV_MAX        clue_LOG_SEV_MAX

# ifndef clue_LOG_TO_SYSLOG
#  define LOG_EMERGENCY     clue_LOG_EMERGENCY
#  define LOG_ALERT         clue_LOG_ALERT
#  define LOG_CRITICAL      clue_LOG_CRITICAL
#  define LOG_ERROR         clue_LOG_ERROR
#  define LOG_WARNING       clue_LOG_WARNING
#  define LOG_NOTICE        clue_LOG_NOTICE
#  define LOG_INFO          clue_LOG_INFO
#  define LOG_DEBUG         clue_LOG_DEBUG
# endif

# define LOG_LOGGED_SEVERITIES   clue_LOG_LOGGED_SEVERITIES
# define LOG_EXPRESSION     clue_LOG_EXPRESSION

#endif // clue_NO_SHORT_NAMES

#ifdef clue_LOG_TO_CONSOLE
# include <iostream>
#endif

#ifdef clue_LOG_TO_FILE
# include <fstream>
#endif

#ifdef clue_LOG_TO_DEBUGGER_WINDOWS
# include <windows.h>
#endif

#ifdef clue_LOG_TO_DEBUGGER_UNIX
# error log to debugger under Unix not implemented
#endif

#ifdef clue_LOG_TO_EVENTLOG
# include <windows.h>
#endif

#ifdef clue_LOG_TO_SYSLOG
# include <syslog.h>
#endif

#define clue_LOG_SEV_NONE      -1
#define clue_LOG_SEV_EMERGENCY  0
#define clue_LOG_SEV_ALERT      1
#define clue_LOG_SEV_CRITICAL   2
#define clue_LOG_SEV_ERROR      3
#define clue_LOG_SEV_WARNING    4
#define clue_LOG_SEV_NOTICE     5
#define clue_LOG_SEV_INFO       6
#define clue_LOG_SEV_DEBUG      7
#define clue_LOG_SEV_MAX        7

#ifndef  clue_LOG_LEVEL
# define clue_LOG_LEVEL         clue_LOG_SEV_DEBUG
#endif

#ifndef  clue_LOG_LEVEL_BUILD
# define clue_LOG_LEVEL_BUILD   clue_LOG_SEV_DEBUG
#endif

#define clue_LOG_SEV_NONE_TEXT       "[clue]"
#define clue_LOG_SEV_EMERGENCY_TEXT  "Emergency"
#define clue_LOG_SEV_ALERT_TEXT      "Alert"
#define clue_LOG_SEV_CRITICAL_TEXT   "Critical"
#define clue_LOG_SEV_ERROR_TEXT      "Error"
#define clue_LOG_SEV_WARNING_TEXT    "Warning"
#define clue_LOG_SEV_NOTICE_TEXT     "Notice"
#define clue_LOG_SEV_INFO_TEXT       "Info"
#define clue_LOG_SEV_DEBUG_TEXT      "Debug"

#ifndef  clue_LOG_MODULE_NAME
# define clue_LOG_MODULE_NAME ""
#endif

#ifndef  clue_LOG_PREFIX_WIDTH
# define clue_LOG_PREFIX_WIDTH      sizeof( clue_LOG_SEV_EMERGENCY_TEXT )
#endif

#define clue_is_active( severity ) \
    clue::is_true( severity <= clue_LOG_LEVEL )

#define clue_is_active_build( severity ) \
    clue::is_true( clue_IS_ACTIVE_BUILD( severity ) )

#define clue_IS_ACTIVE_BUILD( severity ) \
    ( severity <= clue_LOG_LEVEL_BUILD )

#define clue_LOG_LOGGED_SEVERITIES() \
    clue_LOG_EXPRESSION( clue_LOG_SEV_NONE, clue::to_severities_text( clue_LOG_LEVEL_BUILD ) )

#define clue_LOG_NO_EXPRESSION() \
    do {} while( clue::is_true(false) )

#define clue_IS_ACTIVE( severity ) \
    ( clue_IS_ACTIVE_BUILD( severity )  ||  !clue_OMIT_UNUSED_LOG_EXPRESSION )

#if clue_IS_ACTIVE( clue_LOG_SEV_EMERGENCY )
# define clue_LOG_EMERGENCY( expr ) clue_LOG_EXPRESSION( clue_LOG_SEV_EMERGENCY, expr )
#else
# define clue_LOG_EMERGENCY( expr ) clue_LOG_NO_EXPRESSION()
#endif

#if clue_IS_ACTIVE( clue_LOG_SEV_ALERT ) 
# define clue_LOG_ALERT( expr ) clue_LOG_EXPRESSION( clue_LOG_SEV_ALERT, expr )
#else
# define clue_LOG_ALERT( expr ) clue_LOG_NO_EXPRESSION()
#endif

#if clue_IS_ACTIVE( clue_LOG_SEV_CRITICAL )
# define clue_LOG_CRITICAL( expr ) clue_LOG_EXPRESSION( clue_LOG_SEV_CRITICAL, expr )
#else
# define clue_LOG_CRITICAL( expr ) clue_LOG_NO_EXPRESSION()
#endif

#if clue_IS_ACTIVE( clue_LOG_SEV_ERROR )
# define clue_LOG_ERROR( expr ) clue_LOG_EXPRESSION( clue_LOG_SEV_ERROR, expr )
#else
# define clue_LOG_ERROR( expr ) clue_LOG_NO_EXPRESSION()
#endif

#if clue_IS_ACTIVE( clue_LOG_SEV_WARNING )
# define clue_LOG_WARNING( expr ) clue_LOG_EXPRESSION( clue_LOG_SEV_WARNING, expr )
#else
# define clue_LOG_WARNING( expr ) clue_LOG_NO_EXPRESSION()
#endif

#if clue_IS_ACTIVE( clue_LOG_SEV_NOTICE )
# define clue_LOG_NOTICE( expr ) clue_LOG_EXPRESSION( clue_LOG_SEV_NOTICE, expr )
#else
# define clue_LOG_NOTICE( expr ) clue_LOG_NO_EXPRESSION()
#endif

#if clue_IS_ACTIVE( clue_LOG_SEV_INFO )
# define clue_LOG_INFO( expr ) clue_LOG_EXPRESSION( clue_LOG_SEV_INFO, expr )
#else
# define clue_LOG_INFO( expr ) clue_LOG_NO_EXPRESSION()
#endif

#if clue_IS_ACTIVE( clue_LOG_SEV_DEBUG )  &&  !defined( NDEBUG )
# define clue_LOG_DEBUG( expr ) clue_LOG_EXPRESSION( clue_LOG_SEV_DEBUG, expr )
#else
# define clue_LOG_DEBUG( expr ) clue_LOG_NO_EXPRESSION()
#endif

#if defined( clue_LOG_TO_CONSOLE ) && !defined( clue_LOG_EXPRESSION )
# define clue_LOG_EXPRESSION( severity, expr ) \
    do { \
        if ( clue_is_active_build( severity ) ) { \
            if ( clue_is_active( severity ) ) { \
                std::clog << \
                    clue::now_text() << std::setw( clue_LOG_PREFIX_WIDTH ) << \
                    clue::to_severity_text(severity) << \
                    clue::to_module_text(clue_LOG_MODULE_NAME) << ": " << expr << "\n"; \
            } \
        } \
    } while( clue::is_true( false ) )
#endif

#if defined( clue_LOG_TO_FILE ) && !defined( clue_LOG_EXPRESSION )
# define clue_LOG_EXPRESSION( severity, expr ) \
    do { \
        if ( clue_is_active_build( severity ) ) { \
            if ( clue_is_active( severity ) ) { \
                clue::filelog() << \
                    clue::now_text() << std::setw( clue_LOG_PREFIX_WIDTH ) << \
                    clue::to_severity_text(severity) << \
                    clue::to_module_text(clue_LOG_MODULE_NAME) << ": " << expr << "\n"; \
            } \
        } \
    } while( clue::is_true( false ) )
#endif

#if defined( clue_LOG_TO_STRING ) && !defined( clue_LOG_EXPRESSION )
# define clue_LOG_EXPRESSION( sev, expr ) \
    clue_LOG_STRING_EXPRESSION( the_log(), sev, expr )
#endif 

#if defined( clue_LOG_TO_STRING ) && !defined( clue_LOG_STRING_EXPRESSION )
# define clue_LOG_STRING_EXPRESSION( log, sev, expr ) \
    do { \
        if ( clue_is_active_build( sev ) ) { \
            if ( clue_is_active( sev ) ) { \
                log.severity( sev ); \
                log << \
                    clue_LOG_MODULE_NAME << expr; \
            } \
        } \
     } while( clue::is_true(false) )
#endif 

#if defined( clue_LOG_TO_DEBUGGER_WINDOWS ) && !defined( clue_LOG_EXPRESSION )
# define clue_LOG_EXPRESSION( severity, expr ) \
    do { \
        if ( clue_is_active_build( severity ) ) { \
            if ( clue_is_active( severity ) ) { \
                clue::windbg() << \
                    std::setw( clue_LOG_PREFIX_WIDTH ) << clue::to_severity_text( severity ) << \
                    clue::to_module_text(clue_LOG_MODULE_NAME) << ": " << expr; \
            } \
        } \
     } while( clue::is_true(false) )
#endif 

#if defined( clue_LOG_TO_EVENTLOG ) && !defined( clue_LOG_EXPRESSION )
# define clue_LOG_EXPRESSION( severity, expr ) \
    do { \
        if ( clue_is_active_build( severity ) ) { \
            if ( clue_is_active( severity ) ) { \
                clue::evtlog( severity, clue_LOG_MODULE_NAME ) << \
                    clue::text_with_or( "", clue_LOG_MODULE_NAME, ": ", "" ) << expr; \
            } \
        } \
     } while( clue::is_true(false) )
#endif

#if defined( clue_LOG_TO_SYSLOG ) && !defined( clue_LOG_EXPRESSION )
# define clue_LOG_EXPRESSION( severity, expr ) \
    do { \
        if ( clue_is_active_build( severity ) ) { \
            if ( clue_is_active( severity ) ) { \
                clue::syslog( severity ) << \
                    clue_LOG_MODULE_NAME << ": " << expr; \
            } \
        } \
     } while( clue::is_true(false) )
#endif 

namespace clue
{

inline bool is_true( bool const on ) { return on; }

inline std::string text_or( std::string const & text, std::string const & or_text )
{
    return text.length() ? text : or_text;
}

inline std::string text_with_or( std::string const & prefix, std::string const & text, std::string const & postfix, std::string const & or_text )
{
    return text.length() ? prefix + text + postfix: or_text;
}

inline std::string to_module_text( std::string const & module )
{
    return text_with_or( ": ", module, "", "" );
}

inline std::string to_severity_text( int const severity )
{
    assert( clue_LOG_SEV_NONE <= severity && severity <= clue_LOG_SEV_MAX && "invalid severity" );

    if ( severity == clue_LOG_SEV_NONE )
        return clue_LOG_SEV_NONE_TEXT;

    assert( clue_LOG_SEV_EMERGENCY == 0 && "required by lookup table" );

    std::string const cont[] =
    {
        clue_LOG_SEV_EMERGENCY_TEXT,
        clue_LOG_SEV_ALERT_TEXT,
        clue_LOG_SEV_CRITICAL_TEXT,
        clue_LOG_SEV_ERROR_TEXT,
        clue_LOG_SEV_WARNING_TEXT,
        clue_LOG_SEV_NOTICE_TEXT,
        clue_LOG_SEV_INFO_TEXT,
        clue_LOG_SEV_DEBUG_TEXT,
    };
    return cont[ severity ];
}

inline std::string to_severities_text( int const level, std::string const & postfix = ".", std::string const & result = "" )
{
    if ( level < 0 )
        return result + postfix;

    return to_severities_text( level - 1, postfix, to_severity_text( level ) + text_with_or( ", ", result, "", "" ) );
}

} // namespace clue

#ifdef clue_NO_TIMESTAMP

namespace clue {
inline std::string now_text() { return ""; }
}

#else // clue_NO_TIMESTAMP

# include <ctime>

# ifdef clue_COMPILER_IS_MSVC6
namespace std {
using ::time_t; using ::time; using ::strftime; using ::localtime;
}
# endif

namespace clue {

inline std::string now_text()
{
    char mbstr[100];
    const std::time_t now = std::time(NULL);

    // ISO  ISO 8601 date and time format: C++11: %FT%T
    if ( std::strftime( mbstr, 100, "%Y-%m-%dT%H:%M:%S", std::localtime( &now ) ) )
        return mbstr;
    else
        return "[time]";
}
} // namespace clue

#endif // clue_NO_TIMESTAMP

#ifdef clue_LOG_TO_FILE

namespace clue {

class filelog
{
public:
    filelog()
    : stream() {}

    ~filelog()
    {
        // emit: program-name[pid]:
        std::ofstream os( clue_LOG_TO_FILE, std::ios_base::app );
        os << stream.str();
    }

    template<typename T>
    filelog & operator<<( T const & that )
    {
        stream << that;
        return *this;
    }

private:
    std::ostringstream stream;
};

} // namespace clue

#endif // clue_LOG_TO_FILE

#ifdef clue_LOG_TO_STRING

namespace clue {

class strlog
{
public:
    strlog()
    : severity_( clue_LOG_SEV_NONE )
    , stream() {}

    void clear()
    {
        severity_ = clue_LOG_SEV_NONE ;
        stream.str( std::string() );
    }

    void severity( int const sev ) 
    {
        severity_ = sev;
    }

    int severity() const
    {
        return severity_;
    }

    std::string text() const
    {
        return stream.str();
    }

    template<typename T>
    strlog & operator<<( T const & that )
    {
        stream << that;
        return *this;
    }

private:
    int severity_;
    std::ostringstream stream;
};

inline strlog & the_log()
{
    static strlog log;
    return log;
}

} // namespace clue

#endif // clue_LOG_TO_STRING

#ifdef clue_LOG_TO_DEBUGGER_WINDOWS

namespace clue
{

class windbg
{
public:
    windbg() 
    : stream() {}

    ~windbg()
    {
        OutputDebugString( stream.str().c_str() );
    }

    template<typename T>
    windbg & operator<<( T const & that )
    {
        stream << that;
        return *this;
    }

private:
    std::ostringstream stream;
};

} // namespace clue

#endif // clue_LOG_TO_DEBUGGER_WINDOWS

#ifdef clue_LOG_TO_EVENTLOG

namespace clue
{

inline int to_eventlog_severity( int severity )
{
    assert( clue_LOG_SEV_NONE <= severity && severity <= clue_LOG_SEV_MAX && "invalid severity" );

    switch( severity )
    {
        case clue_LOG_SEV_NONE:      return EVENTLOG_INFORMATION_TYPE;
        case clue_LOG_SEV_EMERGENCY: return EVENTLOG_ERROR_TYPE;
        case clue_LOG_SEV_ALERT:     return EVENTLOG_ERROR_TYPE;
        case clue_LOG_SEV_CRITICAL:  return EVENTLOG_ERROR_TYPE;
        case clue_LOG_SEV_ERROR:     return EVENTLOG_ERROR_TYPE;
        case clue_LOG_SEV_WARNING:   return EVENTLOG_WARNING_TYPE;
        case clue_LOG_SEV_NOTICE:    return EVENTLOG_INFORMATION_TYPE;
        case clue_LOG_SEV_INFO:      return EVENTLOG_INFORMATION_TYPE;
        default:
        case clue_LOG_SEV_DEBUG:     return EVENTLOG_INFORMATION_TYPE;
    }
}

class evtlog
{
public:
    evtlog( int const severity, std::string const & module )
    : severity( severity )
    , module( module)
    , stream() {}

    ~evtlog()
    {
        // note string lifetime
        const std::string text = stream.str();
        const char *strings[]  = { text.c_str(), };

        const ::HANDLE hlog = ::RegisterEventSource(
            0, text_or( module, "[clue]" ).c_str() );

        ::ReportEvent(
            hlog          // HANDLE hEventLog,    // handle returned by RegisterEventSource
            , to_eventlog_severity(severity)   // WORD wType, // event type to log
            , 0           // WORD wCategory,      // event category
            , 0           // DWORD dwEventID,     // event identifier
            , 0           // PSID lpUserSid,      // user security identifier (optional)
            , 1           // WORD wNumStrings,    // number of strings to merge with message
            , 0           // DWORD dwDataSize,    // size of binary data, in bytes
            , strings     // LPCTSTR *lpStrings,  // array of strings to merge with message
            , 0           // LPVOID lpRawData     // address of binary data
        );

        ::DeregisterEventSource( hlog );
    }

    template<typename T>
    evtlog & operator<<( T const & that )
    {
        stream << that;
        return *this;
    }

private:
    const int severity;
    const std::string module;
    std::ostringstream stream;
};

} // namespace clue

#endif // clue_LOG_TO_DEBUGGER_WINDOWS

#ifdef clue_LOG_TO_SYSLOG

namespace clue {

inline int to_syslog_severity( int severity )
{
    assert( clue_LOG_SEV_NONE <= severity && severity <= clue_LOG_SEV_MAX && "invalid severity" );

    switch( severity )
    {
        case clue_LOG_SEV_NONE:      return LOG_INFO;
        case clue_LOG_SEV_EMERGENCY: return LOG_EMERG;
        case clue_LOG_SEV_ALERT:     return LOG_ALERT;
        case clue_LOG_SEV_CRITICAL:  return LOG_CRIT;
        case clue_LOG_SEV_ERROR:     return LOG_ERR;
        case clue_LOG_SEV_WARNING:   return LOG_WARNING;
        case clue_LOG_SEV_NOTICE:    return LOG_NOTICE;
        case clue_LOG_SEV_INFO:      return LOG_INFO;    
        default:
        case clue_LOG_SEV_DEBUG:     return LOG_DEBUG;
    }
}

class syslog
{
public:
    syslog( int const severity )
    : severity( severity )
    , stream() {}

    ~syslog()
    {
        // emit: program-name[pid]:
        ::openlog( NULL, LOG_PID, LOG_USER );
        ::syslog ( to_syslog_severity(severity), "%s", stream.str().c_str() );
        ::closelog();
    }

    template<typename T>
    syslog & operator<<( T const & that )
    {
        stream << that;
        return *this;
    }

private:
    const int severity;
    std::ostringstream stream;
};

} // namespace clue

#endif //clue_LOG_TO_SYSLOG

#ifdef clue_COMPILER_IS_MSVC
# pragma warning( pop ) 
#endif

#endif // CLUE_CLUE_H_INCLUDED

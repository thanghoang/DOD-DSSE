/*
 * Author:  David Robert Nadeau
 * Site:    http://NadeauSoftware.com/
 * License: Creative Commons Attribution 3.0 Unported License
 *          http://creativecommons.org/licenses/by/3.0/deed.en_US
 *
 * Usage:
 *	To benchmark an algorithm's CPU time, call getCPUTime( ) at the 
 *  beginning and end, then report the * difference. It is not safe 
 *  to assume the value returned by one function call has any meaning.
 *		double startTime, endTime;
 * 		startTime = getCPUTime( );
 * 		...
 * 		endTime = getCPUTime( );
 * 		fprintf( stderr, "CPU time used = %lf\n", (endTime - startTime) );
 */

#ifndef __JG_TIMING_H__
#define __JG_TIMING_H__
 
#ifdef __cplusplus
extern "C" {
#endif
 

#if defined(_WIN32)
#include <Windows.h>

#elif defined(__unix__) || defined(__unix) || defined(unix) || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#include <sys/resource.h>
#include <sys/times.h>
#include <time.h>

#else
#error "Unable to define getCPUTime( ) for an unknown OS."
#endif

double getCPUTime( void );

#ifdef __cplusplus
}
#endif

#endif /*END __JG_TIMING_H__*/

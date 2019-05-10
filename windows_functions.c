#include "windows_types.h"

#include <sys/time.h>

unsigned long GetTickCount()
{
  struct timeval tv;
  if( gettimeofday(&tv, NULL) != 0 )
    return 0;

  return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}


#ifndef LIBBPF_PRINT_H
#define LIBBPF_PRINT_H

#include <bpf/libbpf.h>
#include <string>

extern bool verbose;

/// libbpf print helper
static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  if (level == LIBBPF_DEBUG && !verbose)
    return 0;
  return vfprintf(stderr, format, args);
}

/// get current time helper
static std::string get_current_time(void) {
  struct tm *tm;
  char ts[32];
  time_t t;

  time(&t);
  tm = localtime(&t);
  strftime(ts, sizeof(ts), "%H:%M:%S", tm);
  return std::string(ts);
}

#endif
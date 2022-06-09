#include <time.h>

struct timespec g_start, g_end;

void start_the_clock(void)
{
	clock_gettime(CLOCK_MONOTONIC, &g_start);
}

void stop_the_clock(void)
{
	clock_gettime(CLOCK_MONOTONIC, &g_end);
}

double get_duration(void)
{
	long ns_duration;
	ns_duration = (g_end.tv_sec-g_start.tv_sec)*1e9;
	ns_duration += g_end.tv_nsec-g_start.tv_nsec;
	return (double)ns_duration/(double)1e9;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#define x8(i) i i i i i i i i
#define x10(i) i i i i i i i i i i
#define asminst(s,a,e) s x8(x8(x8(a))) e

char DENORM = 1;

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
	int ret;
	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
	return ret;
	}

int funl() {

	__asm__ __volatile__ (
	    asminst("", "sub r0, r1, r1; add r0, r0, #0; subs r2, r0, #0; adc r1, r2, #0; adc r1, r2, #0; mla r1, r0, r0, r0;", "")
	    : :  : "r0", "r1", "r2", "r3", "r4", "sp");

	return 0;
}

int main(int argc, char *argv[]) {

	struct perf_event_attr pe;
	long long count;
	int fd;
	memset(&pe, 0, sizeof(struct perf_event_attr));
	pe.type = PERF_TYPE_HARDWARE;
	pe.size = sizeof(struct perf_event_attr);
	pe.config = PERF_COUNT_HW_CPU_CYCLES;
	pe.disabled = 1;
	pe.exclude_kernel = 1;
	pe.exclude_hv = 1;
	fd = perf_event_open(&pe, 0, -1, -1, 0);
	if (fd == -1) {
		fprintf(stderr, "error opening leader\\n");
		exit(EXIT_FAILURE);
	}

	int maxRuns;
	maxRuns = 10;
	
	int i = 0;
	unsigned long long dr, nr, mindr, minnr;
	mindr = 1<<30;
	int subruncount = 50;

	while(++i<=maxRuns) {
		int j = 0;
		--j;
		++j<=subruncount;
		funl();
		ioctl(fd, PERF_EVENT_IOC_RESET, 0);
		ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
		while(++j<=subruncount) {
			funl();
		}
		ioctl(fd, PERF_EVENT_IOC_DISABLE,0);
		read(fd, &count, sizeof(long long));
		dr = count;
		if (dr < mindr) mindr = dr;
	}

	close(fd);

	int instsPRun = 8*8*8*subruncount;

	//print cycles per instruction:
    // 0.04 is a lower bound on the measurement setup error
    // 5 is the number of cycles taken by the auxiliary instructions
	printf("%.1f\n",((float) mindr/instsPRun - 0.04 - 6)/2);

	return 0;
}

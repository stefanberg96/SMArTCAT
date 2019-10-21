#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#define x10(i) i i i i i i i i i i
//#define asminst(s,a,e) s a e
#define asminst(s,a,e) s x10(x10(x10(a))) e

char DENORM = 1;

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
	int ret;
	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
	return ret;
	}

long long funl(int a, int b) {
	int result;

	//printf("%d ",b);

	__asm__ __volatile__ (
	    asminst("mov r0, #2147483647; cmn r0, #2147483647;", "bicseq r1,r2,#0;\n add r0, r0, r0; add r0, r0, r0; add r0, r0, r0; mov r0, #2147483647; cmn r0, #2147483647;", "add %0, r1, #0")
	    : "=r" (result) : "r" (a), "r" (b) : "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8");

	return (long long) result;
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
		fprintf(stderr, "error opening leader\n");
		exit(EXIT_FAILURE);
	}

	int a,b,c,d;
	int aa = (1 << 30)-1 -(1<<29);
	int cc = 10;
	int bb;
	int dd = 2;
	long long aaa = 0;
	long long ccc = 0;
	float t1,t2;
	a = 10000;
	char denorm;
	int maxRuns;
	maxRuns = 50;
	bb = 2;

	int i = 0;
	unsigned long long dr, nr, mindr, minnr;
	mindr = 1<<30;
	int subruncount = 50;

	while(++i<=maxRuns) {
		int j = 0;
		j--;
		++j<subruncount;
		aaa += funl(aa,bb);
		ioctl(fd, PERF_EVENT_IOC_RESET, 0);
		ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
		while(++j<subruncount) {
			aaa += funl(aa,bb);
		}
		ioctl(fd, PERF_EVENT_IOC_DISABLE,0);
		read(fd, &count, sizeof(long long));
		dr = count;
		if (dr < mindr) mindr = dr;
	}

	close(fd);

	int instsPRun = 1000*subruncount;

	//print cycles per instruction:
	printf("%.1f\n",(float) mindr/instsPRun);

	return 0;
}

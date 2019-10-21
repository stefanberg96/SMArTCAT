#define x8(i) i i i i i i i i
#define asminst(s,a,e) s x8(x8(x8(a))) e
#include <stdio.h>
char justOnce = -1;
float OFFSET =  22.04;

int funl(int seed) {

int a;
__asm__ __volatile__ (" mov r0, %1;\
 mov r7, #0;\
 mov r8, #2048;\
 mov r9, #0x200;\
 sub r9, #1;\
 mov r6, #1;\
 add r4, pc, #56;\
 sub r12, pc, #4;\
loopstart: sub r8, #1;\
 mul r5, r1, r2;\
lfsr: lsr r1, r0, #8;\
 lsr r2, r0, #4;\
 lsl r0, #1;\
 eor r1, r2;\
 and r1, #1;\
 orr r0, r1;\
 and r0, r9;\
 nop;\
 cmp r1, #0;\
 nop; nop;\
 beq nojump;\
nojump: nop; nop;\
 cmp r8, #0;\
 movne pc, r12;\
 mov %0, r1;\
"

/*
bl lfsr; nop; takes 21 cycles to execute

 b lfsrreturn;\

linear feedback shift register to mess with branch predictor: x^9 + x^5 + 1
seed = ldr[fp - 128] (it seems different every time)
rand(seed(r0), bit(r1)) {
	bit = (((seed >> 8) ^ (seed >> 4) & 1)
	seed = (seed<<1 | bit) & 0x1ff
	return bit(r1)
}

	r1 = (((r0 >> 8) ^( r0 >> 4) & 1)
	r0 = (r0 << 1 | r1) & r3
	cmp r1 #0

LFSR reference implementation:

 lfsr: lsr r1, r0, #8;\
 lsr r2, r0, #4;\
 eor r1, r2;\
 and r1, #1;\
 mov r2, #0x200;\
 lsl r0, #1;\
 orr r0, r1;\
 sub r2, #1;\
 and r0, r2;\
*/
	    : "=r"(a) : "r"(seed) : "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r12", "sp");

/*	int r0, r1;
	__asm__ __volatile__ ("mov %0, lr;" : "=r"(r0) : );

*/
/*
	if (++justOnce <= 10) {
		printf("number: %u\n", a);
	}
*/
	return 0;
}

#include <asm/unistd.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <time.h>

char DENORM = 1;

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
	int ret;
	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
	return ret;
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
	maxRuns = 50;	
	int i = 0;
	unsigned long long dr, nr, mindr, minnr;
	mindr = 1<<30;
	int subruncount = 1;
	srand(time(NULL));
	while(++i<=maxRuns) {
		int j = 0;
		--j;
		++j<=subruncount;
		int random = rand() % 512;
//		printf("rand: %u\n", random);
//		funl(1);
		ioctl(fd, PERF_EVENT_IOC_RESET, 0);
		ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
		funl(random);
		ioctl(fd, PERF_EVENT_IOC_DISABLE,0);
		read(fd, &count, sizeof(long long));
		dr = count;
		if (dr < mindr) mindr = dr;
	}

	close(fd);

	int instsPRun = 2048*subruncount;

	//print cycles per instruction:
    // 0.04 is a lower bound on the measurement setup error
    // 5 is the number of cycles taken by the auxiliary instructions
	printf("%.2f\n",((float) mindr/instsPRun -OFFSET));

	return 0;
}

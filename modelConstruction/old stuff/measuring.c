
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>

char DENORM = 1;

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
	int ret;
	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
	return ret;
	}

int funl() {

	__asm__ __volatile__ ("; ADC r1, r2, #77; ADCeq r1, r2, #77; ADC r1, r2, r3, LSL #3; ADCeq r1, r2, r3, LSL #3; ADC r1, r2, r3; ADCeq r1, r2, r3; ADC r1, r2, r3, LSL r4; ADCeq r1, r2, r3, LSL r4; ADD r1, r2, #77; ADDeq r1, r2, #77; ADD r1, r2, r3, LSL #3; ADDeq r1, r2, r3, LSL #3; ADD r1, r2, r3; ADDeq r1, r2, r3; ADD r1, r2, r3, LSL r4; ADDeq r1, r2, r3, LSL r4; ADD r1, SP, #77; ADDeq r1, SP, #77; ADD r1, SP, r2, LSL #3; ADDeq r1, SP, r2, LSL #3; ADD r1, SP, r2; ADDeq r1, SP, r2; AND r1, r2, #77; ANDeq r1, r2, #77; AND r1, r2, r3, LSL #3; ANDeq r1, r2, r3, LSL #3; AND r1, r2, r3; ANDeq r1, r2, r3; AND r1, r2, r3, LSL r4; ANDeq r1, r2, r3, LSL r4; ASR r1, r2, #15; ASReq r1, r2, #15; ASR r1, r2, r3; ASReq r1, r2, r3; BIC r1, r2, #77; BICeq r1, r2, #77; BIC r1, r2, r3, LSL #3; BICeq r1, r2, r3, LSL #3; BIC r1, r2, r3; BICeq r1, r2, r3; BIC r1, r2, r3, LSL r4; BICeq r1, r2, r3, LSL r4; BKPT #15; BLX r1; BLXeq r1; BX r1; BXeq r1; CLZ r1, r2; CLZeq r1, r2; CMN r1, #77; CMNeq r1, #77; CMN r1, r2, LSL #3; CMNeq r1, r2, LSL #3; CMN r1, r2; CMNeq r1, r2; CMN r1, r2, LSL r3; CMNeq r1, r2, LSL r3; CMP r1, #77; CMPeq r1, #77; CMP r1, r2, LSL #3; CMPeq r1, r2, LSL #3; CMP r1, r2; CMPeq r1, r2; CMP r1, r2, LSL r3; CMPeq r1, r2, LSL r3; EOR r1, r2, #77; EOReq r1, r2, #77; EOR r1, r2, r3, LSL #3; EOReq r1, r2, r3, LSL #3; EOR r1, r2, r3; EOReq r1, r2, r3; EOR r1, r2, r3, LSL r4; EOReq r1, r2, r3, LSL r4; LDM r1, {r2,r3,r4}; LDMeq r1, {r2,r3,r4}; LDM r1!, {r2,r3,r4}; LDMeq r1!, {r2,r3,r4}; LDMDA r1, {r2,r3,r4}; LDMDA r1!, {r2,r3,r4}; LDMDB r1, {r2,r3,r4}; LDMDB r1!, {r2,r3,r4}; LDMIB r1, {r2,r3,r4}; LDMIB r1!, {r2,r3,r4}; LDR r1, [r2, #+15]; LDReq r1, [r2, #+15]; LDR r1, [r2]; LDReq r1, [r2]; LDR r1, [r2,+r3, LSL #3]; LDReq r1, [r2,+r3, LSL #3]; LDR r1, [r2,+r3, LSL #3]!; LDReq r1, [r2,+r3, LSL #3]!; LDR r1, [r2,+r3]; LDReq r1, [r2,+r3]; LDR r1, [r2,+r3]!; LDReq r1, [r2,+r3]!; LDRB r1, [r2, #+15]; LDRB r1, [r2]; LDRB r1, [r2,+r3, LSL #3]; LDRB r1, [r2,+r3, LSL #3]!; LDRB r1, [r2,+r3]; LDRB r1, [r2,+r3]!; LDRBT r1, [r2], #+15; LDRH r1, [r2, #+15]; LDRH r1, [r2]; LDRH r1, [r2,+r3]; LDRH r1, [r2,+r3]!; LDRSB r1, [r2, #+15]; LDRSB r1, [r2]; LDRSB r1, [r2,+r3]; LDRSB r1, [r2,+r3]!; LDRSH r1, [r2, #+15]; LDRSH r1, [r2]; LDRSH r1, [r2,+r3]; LDRSH r1, [r2,+r3]!; LDRT r1, [r2] , #+15; LDRT r1, [r2] ; LSL r1, r2, #15; LSLeq r1, r2, #15; LSL r1, r2, r3; LSLeq r1, r2, r3; LSR r1, r2, #15; LSReq r1, r2, #15; LSR r1, r2, r3; LSReq r1, r2, r3; MLA r1, r2, r3, r4; MLAeq r1, r2, r3, r4; MOV r1, #77; MOVeq r1, #77; MOV r1, r2; MOVeq r1, r2; MUL r1, r2, r3; MULeq r1, r2, r3; MVN r1, #77; MVNeq r1, #77; MVN r1, r2, LSL #3; MVNeq r1, r2, LSL #3; MVN r1, r2; MVNeq r1, r2; MVN r1, r2, LSL r3; MVNeq r1, r2, LSL r3; NOP; NOPeq; ORR r1, r2, #77; ORReq r1, r2, #77; ORR r1, r2, r3, LSL #3; ORReq r1, r2, r3, LSL #3; ORR r1, r2, r3; ORReq r1, r2, r3; ORR r1, r2, r3, LSL r4; ORReq r1, r2, r3, LSL r4; POP {r1,r2,r3}; POPeq {r1,r2,r3}; PUSH {r1,r2,r3}; PUSHeq {r1,r2,r3}; ROR r1, r2, #15; ROReq r1, r2, #15; ROR r1, r2, r3; ROReq r1, r2, r3; RRX r1, r2; RSB r1, r2, #77; RSBeq r1, r2, #77; RSB r1, r2, r3, LSL #3; RSBeq r1, r2, r3, LSL #3; RSB r1, r2, r3; RSBeq r1, r2, r3; RSB r1, r2, r3, LSL r4; RSBeq r1, r2, r3, LSL r4; RSC r1, r2, #77; RSCeq r1, r2, #77; RSC r1, r2, r3, LSL #3; RSCeq r1, r2, r3, LSL #3; RSC r1, r2, r3; RSCeq r1, r2, r3; RSC r1, r2, r3, LSL r4; RSCeq r1, r2, r3, LSL r4; SMLAL r1, r2, r3, r4; SMLALeq r1, r2, r3, r4; STM r1, {r2,r3,r4}; STMeq r1, {r2,r3,r4}; STM r1!, {r2,r3,r4}; STMeq r1!, {r2,r3,r4}; STMDA r1, {r2,r3,r4}; STMDA r1!, {r2,r3,r4}; STMDB r1, {r2,r3,r4}; STMDB r1!, {r2,r3,r4}; STMIB r1, {r2,r3,r4}; STMIB r1!, {r2,r3,r4}; STR r1, [r2, #+15]; STReq r1, [r2, #+15]; STR r1, [r2]; STReq r1, [r2]; STR r1, [r2,+r3, LSL #3]; STReq r1, [r2,+r3, LSL #3]; STR r1, [r2,+r3, LSL #3]!; STReq r1, [r2,+r3, LSL #3]!; STR r1, [r2,+r3]; STReq r1, [r2,+r3]; STR r1, [r2,+r3]!; STReq r1, [r2,+r3]!; STRB r1, [r2, #+15]; STRB r1, [r2]; STRB r1, [r2,+r3, LSL #3]; STRB r1, [r2,+r3, LSL #3]!; STRB r1, [r2,+r3]; STRB r1, [r2,+r3]!; STRBT r1, [r2], #+15; STRH r1, [r2]; STRH r1, [r2, #+15]; STRH r1, [r2,+r3]; STRH r1, [r2,+r3]!; STRT r1, [r2] , #+15; STRT r1, [r2] ; SUB r1, r2, #77; SUBeq r1, r2, #77; SUB r1, r2, r3, LSL #3; SUBeq r1, r2, r3, LSL #3; SUB r1, r2, r3; SUBeq r1, r2, r3; SUB r1, r2, r3, LSL r4; SUBeq r1, r2, r3, LSL r4; SUB r1, SP, #77; SUBeq r1, SP, #77; SUB r1, SP, r2, LSL #3; SUBeq r1, SP, r2, LSL #3; SUB r1, SP, r2; SUBeq r1, SP, r2; SWP r1, r2, [r3]; SWPB r1, r2, [r3]; TEQ r1, r2, LSL #3; TEQeq r1, r2, LSL #3; TEQ r1, r2; TEQeq r1, r2; TEQ r1, r2, LSL r3; TEQeq r1, r2, LSL r3; TST r1, #77; TSTeq r1, #77; TST r1, r2, LSL #3; TSTeq r1, r2, LSL #3; TST r1, r2; TSTeq r1, r2; TST r1, r2, LSL r3; TSTeq r1, r2, LSL r3; UMLAL r1, r2, r3, r4; UMLALeq r1, r2, r3, r4; UMULL r1, r2, r3, r4; UMULLeq r1, r2, r3, r4"
	    : :  : "r0", "r1", "r2", "r3", "r4", "r7", "sp");

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
		fprintf(stderr, "error opening leader\n");
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
	printf("%.1f\n",(float) mindr/instsPRun - 0.04 - 6);

	return 0;
}

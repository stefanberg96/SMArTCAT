import casmMinimal2 as casm
import logModel
import constructCompileRun2 as ccr
import time

auxiliaries = {"eq": ("sub r0, r1, r1; add r0, r0, #0; subs r2, r0, #0", "sub r0, r1, r1; add r0, r0, #0; subs r2, r0, #1")
,"ne": ("sub r0, r1, r1; add r0, r0, #0; subs r2, r0, #1", "sub r0, r1, r1; add r0, r0, #0; subs r2, r0, #0")
,"cs": ("sub r0, r1, r1; add r0, r0, #0; subs r2, r0, #0", "sub r0, r1, r1; add r0, r0, #0; subs r2, r0, #1")
,"cc": ("sub r0, r1, r1; add r0, r0, #0; subs r2, r0, #1", "sub r0, r1, r1; add r0, r0, #0; subs r2, r0, #0")
,"mi": ("sub r0, r1, r1; add r0, r0, #0; subs r2, r0, #1", "sub r0, r1, r1; add r0, r0, #0; subs r2, r0, #0")
,"pl": ("sub r0, r1, r1; add r0, r0, #0; subs r2, r0, #0", "sub r0, r1, r1; add r0, r0, #0; subs r2, r0, #1")
,"vs": ("sub r0, r1, r1; add r0, r0, #2147483648; adds r2, r0, #2147483648", "sub r0, r1, r1; add r0, r0, #2147483648; adds r2, r0, #0")    #2147483648 = 2^31
,"vc": ("sub r0, r1, r1; add r0, r0, #2147483648; adds r2, r0, #0", "sub r0, r1, r1; add r0, r0, #2147483648; adds r2, r0, #2147483648")
,"hi": ("sub r0, r1, r1; add r0, r0, #1; subs r2, r0, #0", "sub r0, r1, r1; add r0, r0, #1; subs r2, r0, #1")
,"ls": ("sub r0, r1, r1; add r0, r0, #1; subs r2, r0, #1", "sub r0, r1, r1; add r0, r0, #1; subs r2, r0, #0")
,"ge": ("sub r0, r1, r1; add r0, r0, #0; subs r2, r0, #0", "sub r0, r1, r1; add r0, r0, #0; subs r2, r0, #1")
,"lt": ("sub r0, r1, r1; add r0, r0, #0; subs r2, r0, #1", "sub r0, r1, r1; add r0, r0, #0; subs r2, r0, #0")
,"gt": ("sub r0, r1, r1; add r0, r0, #1; subs r2, r0, #0", "sub r0, r1, r1; add r0, r0, #1; subs r2, r0, #1")
,"le": ("sub r0, r1, r1; add r0, r0, #1; subs r2, r0, #1", "sub r0, r1, r1; add r0, r0, #1; subs r2, r0, #0")
,"": "sub r0, r1, r1; add r0, r0, #0; subs r2, r0, #0"}

issueTiming = "mla r1, r3, r3, r3; "   #MLA instruction seems unable to execute in parallel with previous instructions (wrong)
latencyTiming = "mov r7, #1; mla r1, r3, r3, r3; "

#if time equal and instruction cannot execute as younger, then the instruction cannot execute as older.
#if time different (actually lat < iss) and instruction cannot execute as younger, and the instruction does not read from r1! then the instruction can execute as older.
#if it can execute as younger it can also execute as older.

#issueTiming is normal mul timing
#latencyTiming is now mla timing
#hopefully this will make clear which instructions can fast forward

def model():
    asmString = ""
    for format in casm.allInstructions:
        for insn in casm.Formatted(format):
            asmString = "%s; %s" % (asmString, insn[0])
    programcode = createTestProgramCode(asmString)
    ccr.construct(programcode)
    ccr.compile()
            

class testString():
    def __init__(self, insn, cc):
        self.insn = insn
        self.cc = cc
        self.i = 0
        self.maxI = 2 if (self.cc != "" and self.cc != None) else 1
        
    def __iter__(self):
        return self
        
    def next(self):
        if self.i == self.maxI:
            raise StopIteration
        else:
            result = self.insn
            if (self.maxI == 2): #there's a condition code
                if self.i == 0:
                    result = "%s; mul r1, r2, r3; mov r7, #1; %s" % (auxiliaries[self.cc][0], result)
                else:
                    result = "%s; mul r1, r2, r3; mov r7, #1; %s" % (auxiliaries[self.cc][1], result)
            else:
                result = "%s; mov r7, #1; %s" % (auxiliaries[""], result) #this is the non-conditional scenario
            
            self.i += 1
            return result
    
import os    
def measure(code):
    error = ""
    result = -1.0
    retry = 0
    stage = 0
    try:
        constructOut = ccr.construct(code)
        stage += 1
        time.sleep(0.01)
        if constructOut != '':
            print "construction error: %s" % constructOut
        while retry < 5 and constructOut != '' and not (os.path.isfile("./measuring.c") and os.access("./measuring.c", os.X_OK)):
            time.sleep(0.1)
            retry += 1
        #print "attempting compilation"
        compileOut = ccr.compile()
        stage += 1
        time.sleep(0.01)
        retry = 0
        while retry < 5 and not (os.path.isfile("./measuring") and os.access("./measuring", os.X_OK)):
            time.sleep(0.1)
            retry += 1
        result = float(ccr.run())
        stage += 1
        time.sleep(0.01)
        if os.path.isfile("./measuring") or os.path.isfile("./measuring.c"):
            if ccr.cleanup():
                raise Exception
    except Exception as e:
        error = "%s, timing: %0.1f" % (constructErrorMessage(stage), result)
        try:
            if os.path.isfile("./measuring") or os.path.isfile("./measuring.c"):
                ccr.cleanup()
        except:
            if os.path.isfile("./measuring") or os.path.isfile("./measuring.c"):
                error = "%s; failed to cleanup" % error
        if type(result) != float or result == -1:
            result = error
    return result
    
err = None
    
def constructErrorMessage(stage):
    if stage == 0 or stage == 1 and not (os.path.isfile("./measuring.c") and os.access("./measuring.c", os.X_OK)):
        error = "error: failed code construction"
    elif stage == 1 or stage == 2 and not (os.path.isfile("./measuring") and os.access("./measuring", os.X_OK)):
        error = "error: failed to compile code"
    elif stage == 2:
        error = "error: failed to run"
    else:
        error = "error: failed to cleanup program"
    return error
    
def createTestProgramCode(asmString):
    return "%s%s%s" % (programStart, asmString, programEnd)

#define asminst(s,a,e) s a a e

    
programStart = """
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

	__asm__ __volatile__ (\""""

programEnd = """"
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
	printf("%.1f\\n",(float) mindr/instsPRun - 0.04 - 6);

	return 0;
}
"""

model()

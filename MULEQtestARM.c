#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <math.h>

char DENORM = 1;

int fun(int a, int b) {
	int result = 0;
	//__asm__ __volatile__ ("rdtsc" : "=A" (d) );
	__asm__ __volatile__ ("cmp %2, $0; muleq r1, %1, %2; muleq r1, r1, %2; muleq r1, r1, %2; str r1, %0" : "=m" (result) : "r" (a), "r" (b) : "r1");
	return result;
}

int main(int argc, char *argv[]) {
	int a,b,c,d, maxRuns;
	char denorm;
	float t1,t2;
	a = 1;
	printf("usage: taskset -c 1 test [denorm: 1/0] [maxRuns]\n");
	if (argc < 3) { maxRuns = 10000; }
	else { maxRuns = atoi(argv[2]); }
	if (argc < 2) { denorm = DENORM; }
	else { denorm = atoi(argv[1]); }
	if (denorm) {
		b = 0;
	} else {
		b = 2;
	}
	c = (1<<30) -1;
	d = 2;

	printf("c at start: %d\n",c);

	int i = 0;
	clock_t start, end;
	double dentotal = 0, normtotal = 0;
	long long res;
	long long dentotalr=0, normtotalr=0;

	int subruncount = 1000;

	while(++i<maxRuns) {
		int j = 0;
		start = clock();
		while(++j<subruncount) {
			a = fun(a,b);
//			if (a!=0) printf("%0e\n",a);
		}
		end = clock();
		dentotal += (double) end-start;

		j=0;
		start = clock();
		while(++j<subruncount) {
			c = fun(c,d);
		}
		end = clock();
		normtotal += (double) end-start;

		if(i<maxRuns/10) {
			dentotal = 0;
			normtotal = 0;
		}
	}

	printf("done\n");
	printf("total denorm time: %0.f\n", dentotal);
	printf("  total norm time: %0.f\n", normtotal);
	printf("time difference: %0.f\n", dentotal-normtotal);
	printf("time difference: %.5f%\n", fabs(100-fabs(100*dentotal/normtotal)));

	printf("a: %d\n",a);
	printf("c: %d\n",c);

	return 0;
}

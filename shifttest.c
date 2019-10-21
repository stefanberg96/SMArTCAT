//a small test program to test whether shifts display different time depending on input
#include <stdio.h>
#include <string.h>
#include <time.h>

static inline unsigned long long tick() 
{
        unsigned long long d;
        __asm__ __volatile__ ("rdtsc" : "=A" (d) );
        return d;
}

int fun(int a, int b){
    return a >> b;
}

int main( ) {
    int a,b,c,d;
    float t1,t2;
    a = 5;
    /*/
        b = 2000;
    /*/
        b = 0;
    //*/
    c = 5;
    d = 2;
    
    
    int i = 0;
   
    clock_t start, end;
    double dentotal=0, normtotal=0;
    
    long long res;
    long long dentotalr=0, normtotalr=0;
    
    int maxRuns = 10000;
    int subruncount = 10000;
    while(i<maxRuns) {
        int j = 0;
        start = clock();        
        //res=tick();
        while(++j<subruncount) {
            fun(a,b);
        }
        //dentotalr +=  tick()-res;
        end = clock();
        //if (a > 1.01e-38) a = 0;
        //if ((double) end-start < 30) {
            dentotal += (double) end-start;
            //printf("run A: %f\n", (double) end-start);
        //}
        
        j = 0;
        start = clock();
        //res=tick();
        while(++j<subruncount) {
            fun(c,d);
        }
        //normtotalr +=  tick()-res;
        end = clock();
        //c = c/10000;
        //if ((double) end-start < 30) {
            normtotal += (double) end-start;
            //printf("run B: %f\n", (double) end-start);
        //}
        
        //drop first 10% of measurements
        if (i<maxRuns/10) {
            dentotal = 0;
            normtotal = 0;
        }
        ++i;
    }
    
    printf("done\n");
    printf("total denormal time: %.0f\n", dentotal);
    printf("  total normal time: %.0f\n", normtotal);
    printf("total denormal rdtsc: %lld\n", dentotalr);
    printf("  total normal rdtsc: %lld\n", normtotalr);
    //printf("a: %.50f\n", a);
    if (a != 0) printf("a: %d\n", a);
    printf("c: %d\n", c);
    
    return 0;
}
//a bullshit program playing aroudn with arrows
#include <stdio.h>
#include <string.h>
#include <time.h>

struct SomeStruct {
  int d;
};

int main( ) {
  int a,b,e;
  a = 4;
  b = 1;
  e = 1;
  struct SomeStruct q;
  q.d = 5;
  struct SomeStruct* c = &q;
  
  printf("%d\n",c->d);
  printf("%d\n",c->d-->e);
  printf("%d\n",b>c->d-->e);
  printf("%d\n",a>>b>c->d-->e);

    printf("done\n");
    
    return 0;
}

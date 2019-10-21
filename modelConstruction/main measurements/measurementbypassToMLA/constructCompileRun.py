import subprocess

def construct(code):
    out = ""
    try:
        f = open("measuring.c","w") 
        f.write(code)
        f.close()
    except:
        out = "failed to construct c code"
    return out
        
    
def compile():
    #print "compiling"
    # 2> /dev/null
    out = subprocess.check_output("gcc measuring.c -O0 -w -Wa,-W -o measuring 2> /dev/null", shell=True)
    return out
    
def run():
    #print "running"
    out = subprocess.check_output("./measuring", shell=True)
    return out
    
def cleanup():
    #print "cleaning"
    problem = False
    try:
        subprocess.check_output("rm measuring.c 2> /dev/null", shell=True)
    except:
        problem = True
    try:
        subprocess.check_output("rm measuring 2> /dev/null", shell=True)
    except:
        problem = True
    return problem
    
def test():
    code = """#include<stdio.h>
    main()
    {
        printf("Hello World");
        return 0;
    }"""
    try:
        cleanup()
        construct(code)
        compile()
        hi = run()
        print "computer says: \"%s\"" % hi
    except:
        print "error"
        
#test()

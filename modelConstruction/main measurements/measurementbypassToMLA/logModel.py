import time
date = time.strftime("%Y-%m-%d--%H.%M")
logFile = "model-%s.log" % date
f = open(logFile,"w") 

def log(instruction, issueingTime, latency, notes=None):
    entry = "%s;  --  %.1f, %.1f" % (instruction, issueingTime, latency)
    if notes != None:
        entry = "%s;  --  %s" % (entry, notes)
        
    entry = "%s\n" % entry
    try:
        f.write(entry)
        f.flush()
    except:
        print "error during writing entry: %s" % entry
    
def wrapup():
    f.close()
    
    
def test():
    log("mul", 1, 3)
    log("mul", 0, 0, "errored")
    wrapup()
    
#test()

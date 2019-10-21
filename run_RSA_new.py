#run_RSA_new
# calls RSA_new to initialize RSA
#unfortunately, there are 200 distinct paths, after 400 seconds

import settings
import claripy
settings.WARNING_ADDRESS = 0x4885B4DF
settings.WARNING_MOMENT = settings.WARNING_AFTER
settings.VERBOSE = False
settings.TARGET_ADDRESS = 0x514030
settings.TARGET_FUNCTION = "RSA_new"
#settings.TARGET_ADDRESS = 0x513E60
#settings.TARGET_FUNCTION = "RSA_new_method"
settings.TARGET_BINARY = "/home/roeland/Documents/opensslARM/bin/lib/libcrypto.so.1.1"

#settings.outputBuf = 120000

#settings.dataBuf = 100000
#settings.data = claripy.BVS('data', 1024)

#settings.keyBuf = 110000
settings.key = claripy.BVS("key", 1024)

#settings.params = [settings.dataBuf, settings.outputBuf, settings.keyBuf]
settings.params = []

settings.secret = settings.key
from pluginTime import TIME_STRATEGY_SHORTEST_IF_NONSECRET
TIME_STRATEGY = TIME_STRATEGY_SHORTEST_IF_NONSECRET

from pipelineModel import LATENCY_STRATEGY_SHORTEST_IF_NONSECRET
settings.LATENCY_STRATEGY = LATENCY_STRATEGY_SHORTEST_IF_NONSECRET

settings.PG_EXPLORE_ARGUMENTS = {"find": 0x513F6C, "num_find"=50} # , "avoid": 0x4CC4BC

settings.analysis = False

def stateInit(startState):
    """stateInit is called before symbolic execution starts. Override it to initialize the starting state."""
    print "state initialized"
    startState.memory.store(settings.keyBuf, settings.key, 1024)
    startState.memory.store(settings.dataBuf, settings.data, 1024)
    return True


#settings.stateInit = stateInit

import tool
from __future__ import print_function
#openssl encrypt example: http://stackoverflow.com/questions/9889492/how-to-do-encryption-using-aes-in-openssl
#run_bf_encrypt
                      
import settings
import claripy
settings.WARNING_ADDRESS = 0x45dfa0
settings.VERBOSE = True#False
settings.TARGET_ADDRESS = 0x045DF70
settings.TARGET_FUNCTION = "BF_encrypt"
settings.TARGET_BINARY = "/home/roeland/Documents/opensslARM/bin/lib/libcrypto.so.1.1"

settings.dataBuf = 100000
settings.data = claripy.BVS('data', 1024)

settings.keyBuf = 110000
settings.key = claripy.BVS("key", 33600)

settings.params = [settings.dataBuf, settings.keyBuf]

settings.secret = settings.key.concat(settings.data)
#from pluginTime import TIME_STRATEGY_SHORTEST
#settings.TIME_STRATEGY = TIME_STRATEGY_SHORTEST
#settings.PG_EXPLORE_ARGUMENTS = find=(settings.WARNING_ADDRESS,), avoid=(0x43F8F0,0x43F7D0)
from pluginTime import TIME_STRATEGY_SHORTEST_IF_NONSECRET
TIME_STRATEGY = TIME_STRATEGY_SHORTEST_IF_NONSECRET

from pipelineModel import LATENCY_STRATEGY_SHORTEST_IF_NONSECRET
settings.LATENCY_STRATEGY = LATENCY_STRATEGY_SHORTEST_IF_NONSECRET

def stateInit(startState):
    """stateInit is called before symbolic execution starts. Override it to initialize the starting state."""
    print("state initialized")
    startState.memory.store(settings.keyBuf, settings.key, 33600)
    startState.memory.store(settings.dataBuf, settings.data, 1024)
    return True

#from angr.path_group import PathGroup
#PathGroup.old_explore = PathGroup.explore
#def new_explore(_self):
#    print "exploring for target"
#    return _self.old_explore(find=(settings.WARNING_ADDRESS,), avoid=(0x43F850,0x43F7D0))
#PathGroup.explore = new_explore

def warning_funct(state, insn):
    raise Exception

settings.warning_function = warning_funct
settings.WARNING_MOMENT = settings.WARNING_AFTER

settings.stateInit = stateInit

import tool
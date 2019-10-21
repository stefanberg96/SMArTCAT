from __future__ import print_function
#run_DES_set_key_unchecked
#                  int DES_set_key_unchecked(const_DES_cblock *key, DES_key_schedule *schedule)

import settings
import claripy
settings.WARNING_ADDRESS = 0x4a1cb0
settings.WARNING_MOMENT = settings.WARNING_AFTER
settings.VERBOSE = True#False
settings.TARGET_ADDRESS = 0x4A1B10
settings.TARGET_FUNCTION = "DES_set_key_unchecked"
settings.TARGET_BINARY = "/home/roeland/Documents/opensslARM/bin/lib/libcrypto.so.1.1"

settings.outputBuf = 100000
settings.output = claripy.BVS('output', 1024)

settings.keyBuf = 110000
settings.key = claripy.BVS("key", 512)

settings.params = [settings.keyBuf, settings.outputBuf]

settings.secret = settings.key
from pluginTime import TIME_STRATEGY_SHORTEST_IF_NONSECRET
TIME_STRATEGY = TIME_STRATEGY_SHORTEST_IF_NONSECRET

from pipelineModel import LATENCY_STRATEGY_SHORTEST_IF_NONSECRET
settings.LATENCY_STRATEGY = LATENCY_STRATEGY_SHORTEST_IF_NONSECRET

def stateInit(startState):
    """stateInit is called before symbolic execution starts. Override it to initialize the starting state."""
    print("state initialized")
    startState.memory.store(settings.keyBuf, settings.key, 512)
    return True


settings.stateInit = stateInit

import tool
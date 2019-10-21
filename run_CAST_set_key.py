from __future__ import print_function
#run_CAST_set_key
#                      CAST_set_key(CAST_KEY *key, int len, const unsigned char *data)

import settings
import claripy
settings.WARNING_ADDRESS = 0x489AE4
settings.WARNING_MOMENT = settings.WARNING_AFTER
settings.VERBOSE = True#False
settings.TARGET_ADDRESS = 0x489820 
settings.TARGET_FUNCTION = "CAST_set_key"
settings.TARGET_BINARY = "/home/roeland/Documents/opensslARM/bin/lib/libcrypto.so.1.1"

settings.keyBuf = 110000
settings.key = claripy.BVS("key", 1024)

settings.outputBuf = 120000

settings.keyBitLength = claripy.BVS("keyLength", 32)

settings.params = [settings.outputBuf, settings.keyBitLength, settings.keyBuf]

settings.secret = settings.key

from pluginTime import TIME_STRATEGY_SHORTEST_IF_NONSECRET
TIME_STRATEGY = TIME_STRATEGY_SHORTEST_IF_NONSECRET

from pipelineModel import LATENCY_STRATEGY_SHORTEST_IF_NONSECRET
settings.LATENCY_STRATEGY = LATENCY_STRATEGY_SHORTEST_IF_NONSECRET

def stateInit(startState):
    """stateInit is called before symbolic execution starts. Override it to initialize the starting state."""
    print("state initialized")
    startState.memory.store(settings.keyBuf, settings.key, 1024)
    return True


settings.stateInit = stateInit

import tool
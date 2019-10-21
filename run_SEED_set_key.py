from __future__ import print_function
#run_SEED_set_key
#WARNING: best concretize key length! (either 128 or something small, to show different timing channels)
#                  void SEED_set_key(const unsigned char rawkey[SEED_KEY_LENGTH],
#                  SEED_KEY_SCHEDULE *ks)

import settings
import claripy
settings.WARNING_ADDRESS = 0x50f1d8
settings.WARNING_MOMENT = settings.WARNING_AFTER
settings.VERBOSE = True
settings.TARGET_ADDRESS = 0x51A464
settings.TARGET_FUNCTION = "SEED_set_key"
settings.TARGET_BINARY = "/home/roeland/Documents/opensslARM/bin/lib/libcrypto.so.1.1"

settings.outputBuf = 100000

settings.keyBuf = 110000
settings.key = claripy.BVS("key", 10000)

settings.params = [settings.keyBuf, settings.outputBuf]

settings.secret = settings.key
from pluginTime import TIME_STRATEGY_SHORTEST_IF_NONSECRET
TIME_STRATEGY = TIME_STRATEGY_SHORTEST_IF_NONSECRET

from pipelineModel import LATENCY_STRATEGY_SHORTEST_IF_NONSECRET
settings.LATENCY_STRATEGY = LATENCY_STRATEGY_SHORTEST_IF_NONSECRET

def stateInit(startState):
    """stateInit is called before symbolic execution starts. Override it to initialize the starting state."""
    print("state initialized")
    startState.memory.store(settings.keyBuf, settings.key, 10000)
    return True


settings.stateInit = stateInit

import tool
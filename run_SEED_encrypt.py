from __future__ import print_function
#run_SEED_encrypt
#                     void SEED_encrypt(const unsigned char s[SEED_BLOCK_SIZE],
#                  unsigned char d[SEED_BLOCK_SIZE],
#                  const SEED_KEY_SCHEDULE *ks)

import settings
import claripy
settings.WARNING_ADDRESS = 0x4885B4DF
settings.WARNING_MOMENT = settings.WARNING_AFTER
settings.VERBOSE = True#False
settings.TARGET_ADDRESS = 0x51B210
settings.TARGET_FUNCTION = "SEED_encrypt"
settings.TARGET_BINARY = "/home/roeland/Documents/opensslARM/bin/lib/libcrypto.so.1.1"

settings.outputBuf = 120000

settings.dataBuf = 100000
settings.data = claripy.BVS('data', 1024)

settings.keyBuf = 110000
settings.key = claripy.BVS("key", 1024)

settings.params = [settings.dataBuf, settings.outputBuf, settings.keyBuf]

settings.secret = settings.key.concat(settings.data)
from pluginTime import TIME_STRATEGY_SHORTEST_IF_NONSECRET
TIME_STRATEGY = TIME_STRATEGY_SHORTEST_IF_NONSECRET

from pipelineModel import LATENCY_STRATEGY_SHORTEST_IF_NONSECRET
settings.LATENCY_STRATEGY = LATENCY_STRATEGY_SHORTEST_IF_NONSECRET

def stateInit(startState):
    """stateInit is called before symbolic execution starts. Override it to initialize the starting state."""
    print("state initialized")
    startState.memory.store(settings.keyBuf, settings.key, 1024)
    startState.memory.store(settings.dataBuf, settings.data, 1024)
    return True


settings.stateInit = stateInit

import tool
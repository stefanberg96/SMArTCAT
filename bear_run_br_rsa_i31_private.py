#void test_RSA_core(unsigned num_rDCounds, const uint32_t *skey, uint32_t *q);
#bear_run_br_rsa_i31_private
import settings
import claripy
settings.WARNING_ADDRESS = 0x419e20
settings.WARNING_MOMENT = settings.WARNING_AFTER
settings.VERBOSE = True
settings.TARGET_ADDRESS = 0x419DC8
settings.TARGET_FUNCTION = "br_rsa_i31_private"
settings.PC_ONLY = False
settings.OUTPUT_FREQUENCY = 256
settings.TARGET_BINARY = "/home/roeland/Documents/bearssl-0.4-compiled/build/libbearssl.so"
#settings.numrounds = 10
settings.key = claripy.BVS("key", 10000)
settings.message = claripy.BVS("message", 10000)
settings.pointerToKeyStruct = 10000 #0x2710
settings.pointerToKey = 0x80808080  #storing this value makes
settings.pointerToMessage = 50000
settings.params = [settings.pointerToMessage, settings.pointerToKeyStruct]
settings.secret = settings.key.concat(settings.message)
from pluginTime import TIME_STRATEGY_SHORTEST
settings.TIME_STRATEGY = TIME_STRATEGY_SHORTEST
#settings.PG_EXPLORE_ARGUMENTS = {"find": 0x419DFC, "avoid":0x419DE8}

def stateInit(startState):
    """stateInit is called before symbolic execution starts. Override it to initialize the starting state."""
    i = 0
    while i < 1024:
        startState.memory.store(settings.pointerToKeyStruct+i, settings.pointerToKey, 4)
        if i == 8 or i == 4 or i == 12:
            startState.memory.store(settings.pointerToKeyStruct+i, 0x00000010, 4)
        i += 4
    startState.memory.store(settings.pointerToKey, settings.key, 10000)
    startState.memory.store(settings.pointerToMessage, settings.message, 10000)
    startState.regs.sp = 0xff0000
    
    return True

settings.stateInit = stateInit

import tool
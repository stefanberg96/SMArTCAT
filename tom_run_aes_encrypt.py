#void _rijndael_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey) 
#run with 2 rounds
#tom_run_aes_encrypt
#yes, again cache timing channels of course
import settings
import claripy
settings.WARNING_ADDRESS = 0x43fff8
settings.WARNING_MOMENT = settings.WARNING_AFTER
settings.VERBOSE = True
settings.TARGET_ADDRESS = 0x40bee4
settings.TARGET_FUNCTION = "rijndael_ecb_encrypt"
settings.PC_ONLY = False
settings.OUTPUT_FREQUENCY = 256
settings.TARGET_BINARY = "/media/sf_share/libtomcrypt.so"
settings.numrounds = 2
settings.roundkeyPointer = 40000
settings.key = claripy.BVS("key", 128)
settings.message = claripy.BVS("message", 1000)
settings.pointerToMessage = 10000
settings.pointerToCipher = 20000
settings.pointerToKey = 30000

settings.params = [settings.pointerToMessage, settings.pointerToCipher, settings.pointerToKey]
settings.secret = settings.key.concat(settings.message)
from pluginTime import TIME_STRATEGY_SHORTEST
settings.TIME_STRATEGY = TIME_STRATEGY_SHORTEST

def stateInit(startState):
    """stateInit is called before symbolic execution starts. Override it to initialize the starting state."""
    startState.memory.store(settings.pointerToKey, settings.roundkeyPointer, 0)
    startState.memory.store(settings.pointerToKey, settings.roundkeyPointer, 4)
    startState.memory.store(settings.pointerToKey, settings.numrounds, 8)
    startState.memory.store(settings.roundkeyPointer, settings.key, 1024)
    startState.memory.store(settings.pointerToMessage, settings.message, 1024)
    return True

settings.stateInit = stateInit

import tool
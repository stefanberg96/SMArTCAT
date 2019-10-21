#openssl encrypt example: http://stackoverflow.com/questions/9889492/how-to-do-encryption-using-aes-in-openssl
#run_aes_encrypt
import settings
import claripy
settings.WARNING_ADDRESS = 0x43fff8
settings.WARNING_MOMENT = settings.WARNING_AFTER
settings.VERBOSE = True#False
settings.TARGET_ADDRESS = 0x43FDD8
settings.TARGET_FUNCTION = "AES_encrypt"
settings.TARGET_BINARY = "/home/roeland/Documents/opensslARM/bin/lib/libcrypto.so.1.1"
settings.key = claripy.BVS("key", 128)
settings.message = claripy.BVS("message", 128)
settings.params = [settings.pointerToMessage, settings.outputBufferPointer, settings.pointerToKey]
settings.secret = settings.key.concat(settings.message)
from pluginTime import TIME_STRATEGY_SHORTEST
settings.TIME_STRATEGY = TIME_STRATEGY_SHORTEST

def stateInit(startState):
    """stateInit is called before symbolic execution starts. Override it to initialize the starting state."""
    startState.memory.store(settings.pointerToKey, settings.key, 128)
    startState.memory.store(settings.pointerToMessage, settings.message, 128)
    startState.memory.store(settings.pointerToMessage+1*8, 0, 8)
    return True

settings.stateInit = stateInit

import tool
#openssl encrypt example: http://stackoverflow.com/questions/9889492/how-to-do-encryption-using-aes-in-openssl
#run_aes_set_encrypt_key
import settings
import claripy
settings.WARNING_ADDRESS = 0x43fa84
settings.WARNING_MOMENT = settings.WARNING_AFTER
settings.VERBOSE = True#False
settings.TARGET_ADDRESS = 0x043F6B8
settings.TARGET_FUNCTION = "AES_set_encrypt_key"
settings.TARGET_BINARY = "/home/roeland/Documents/opensslARM/bin/lib/libcrypto.so.1.1"
settings.key = claripy.BVS("key", 256)
settings.message = claripy.BVS("message", 8)
settings.keyLength = claripy.BVS("keyLength", 32)
settings.params = [settings.pointerToKey, settings.keyLength, settings.outputBufferPointer]
settings.secret = settings.key
from pluginTime import TIME_STRATEGY_SHORTEST
settings.TIME_STRATEGY = TIME_STRATEGY_SHORTEST
#settings.PG_EXPLORE_ARGUMENTS = find=(settings.WARNING_ADDRESS,), avoid=(0x43F8F0,0x43F7D0)

def stateInit(startState):
    """stateInit is called before symbolic execution starts. Override it to initialize the starting state."""
    startState.memory.store(settings.pointerToKey, settings.key, 256)
    #startState.se.add(claripy.Or(settings.key == 0, settings.key == 1))
    return True

settings.stateInit = stateInit

import tool
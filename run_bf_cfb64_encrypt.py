from __future__ import print_function
#openssl encrypt example: http://stackoverflow.com/questions/9889492/how-to-do-encryption-using-aes-in-openssl
#run_bf_cfb64_encrypt

#void BF_cfb64_encrypt(const unsigned char *in, unsigned char *out,
#                      long length, const BF_KEY *schedule,
#                      unsigned char *ivec, int *num, int encrypt)
                      
import settings
import claripy
settings.WARNING_ADDRESS = 0x45dfa0
settings.VERBOSE = True#False
settings.TARGET_ADDRESS = 0x045DCE0
settings.TARGET_FUNCTION = "BF_cfb64_encrypt"
settings.TARGET_BINARY = "/home/roeland/Documents/opensslARM/bin/lib/libcrypto.so.1.1"

settings.inbuf = 102048#claripy.BVS("inbuf", 32)
settings.instring = claripy.BVS("instring", 32)
settings.outbuf = 104096#claripy.BVS("inbuf", 32)
settings.length = 4
settings.key = claripy.BVS("key", 256)
settings.ivbuf = 101536#claripy.BVS("inbuf", 32)
settings.ivstring = claripy.BVS("IVstring", 32)
settings.numbuf = 105000
settings.num = claripy.BVS("num", 32)
settings.encrypt = claripy.BVS("encrypt", 1)

settings.params = [settings.inbuf, settings.outbuf, settings.length, settings.pointerToKey, settings.ivbuf, settings.numbuf, settings.encrypt]

settings.secret = settings.key.concat(settings.instring)
from pluginTime import TIME_STRATEGY_SHORTEST
settings.TIME_STRATEGY = TIME_STRATEGY_SHORTEST
#settings.PG_EXPLORE_ARGUMENTS = find=(settings.WARNING_ADDRESS,), avoid=(0x43F8F0,0x43F7D0)

def stateInit(startState):
    """stateInit is called before symbolic execution starts. Override it to initialize the starting state."""
    startState.memory.store(settings.pointerToKey, settings.key, 256)
    startState.memory.store(settings.inbuf, settings.instring, 32)
    startState.se.add(settings.instring[8:0] == 0)
    startState.memory.store(settings.ivbuf, settings.ivstring, 32)
    startState.memory.store(settings.numbuf, settings.num, 32)
    #startState.se.add(claripy.Or(settings.key == 0, settings.key == 1))
    return True
    
#from angr.path_group import PathGroup
#PathGroup.old_explore = PathGroup.explore
def new_explore(_self):
    print("exploring for target")
    return _self.old_explore(find=(settings.WARNING_ADDRESS,), avoid=(0x43F850,0x43F7D0))
#PathGroup.explore = new_explore


settings.stateInit = stateInit

import tool
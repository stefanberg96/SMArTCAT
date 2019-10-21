#void br_aes_ct_bitslice_encrypt(unsigned num_rounds, const uint32_t *skey, uint32_t *q);
#run with 2 rounds
#bear_run_aes_encrypt
#full analysis, with TIME_STRATEGY_SHORTEST: 24.1 seconds       1037 cycles    
#full analysis, 10 round with TIME_STRATEGY_SHORTEST: 3:18:20
#TODO: verify time with full 10 rounds for both shortest and pc only (-> hangs as well? or nah 3584 at 3:48)) (CRASHED at 16:02). should note in report that claripy tends to hang sometimes when processing very large expressions. cached unsat.
#full analysis, with TIME_STRATEGY_AVERAGE: 25.3 seconds       6858 cycles
#full analysis, with TIME_STRATEGY_NO_CHANGE: started at 2:07:00     (10:20 (200 secs) for first 40 instructions 100 at 12:40 (340 secs), 120 at 13:10 (370 secs))  stopped after 1 hour. analysis got stuck between insn 260 (0x26020) and 280, after having to wait symbolically for the IP.  full symbolic pipeline simulation without concretization seems infeasible for realistic programs.
#pc analysis: 21.2 seconds                                      912 count
import settings
import claripy
settings.WARNING_ADDRESS = 0x43fff8
settings.WARNING_MOMENT = settings.WARNING_AFTER
settings.VERBOSE = False
settings.TARGET_ADDRESS = 0x426074
settings.TARGET_FUNCTION = "br_aes_ct_bitslice_encrypt"
settings.PC_ONLY = False
settings.OUTPUT_FREQUENCY = 256
settings.TARGET_BINARY = "/home/roeland/Documents/bearssl-0.4-compiled/build/libbearssl.so"
settings.numrounds = 10
settings.key = claripy.BVS("key", 128)
settings.message = claripy.BVS("message", 128)
settings.params = [settings.numrounds, settings.pointerToKey, settings.pointerToMessage]
settings.secret = settings.key.concat(settings.message)
from pluginTime import TIME_STRATEGY_SHORTEST
settings.TIME_STRATEGY = TIME_STRATEGY_SHORTEST

def stateInit(startState):
    """stateInit is called before symbolic execution starts. Override it to initialize the starting state."""
    startState.memory.store(settings.pointerToKey, settings.key, 1024)
    startState.memory.store(settings.pointerToMessage, settings.message, 1024)
    #startState.memory.store(settings.pointerToMessage+1*8, 0, 8)
    return True

settings.stateInit = stateInit

import tool
import settings
import claripy
settings.WARNING_ADDRESS = 0x1fcb0
settings.VERBOSE = True
settings.DEBUG = True
settings.TARGET_BINARY = "/home/stefan/Documents/Graduation/RISC-V-toolchain/riscv/Programs/Poly1305_onetimeauth/Radix2.26_woMultiplier/program.elf"
settings.TARGET_ADDRESS = 0x20010ce8
settings.result = claripy.BVS("a", 16*8)
settings.pointerResult=100000
settings.c = claripy.BVS("b", 130*8)
settings.pointerC=110000
settings.rs = claripy.BVS("rs",32*8)
settings.pointerRS=120000
settings.mlen = claripy.BVV(20, 32);
settings.params = [settings.pointerResult, settings.pointerC, settings.mlen, settings.pointerRS]
settings.secret = settings.rs.concat(settings.c)
from pluginTime import TIME_STRATEGY_SHORTEST
settings.TIME_STRATEGY = TIME_STRATEGY_SHORTEST
def stateInit(startState):
    startState.memory.store(settings.pointerResult, settings.result, 16)
    startState.memory.store(settings.pointerC, settings.c, 130)
    startState.memory.store(settings.pointerRS, settings.rs, 32)
    return True
settings.stateInit = stateInit
import tool

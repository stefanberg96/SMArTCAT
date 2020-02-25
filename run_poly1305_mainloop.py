import settings
import claripy
settings.WARNING_ADDRESS = 0x1fcb0
settings.VERBOSE = True
settings.DEBUG = True
settings.TARGET_BINARY = "/home/stefan/Documents/Graduation/RISC-V-toolchain/riscv/Programs/WithoutMultiplication/Poly1305/Radix2.26_woMultiplier/program.elf"
settings.TARGET_ADDRESS = 0x20011f04
settings.inparam = claripy.BVS("in", 35*8)
settings.pointerInparam=100000
settings.h = claripy.BVS("h", 20*8)
settings.pointerH=110000
settings.r = claripy.BVS("r", 20*8)
settings.pointerR=120000
settings.c = claripy.BVS("c", 20*8)
settings.pointerC=130000
settings.mlen = claripy.BVV(18, size=32)
settings.params = [settings.pointerInparam, settings.mlen, settings.pointerH, settings.pointerR, settings.pointerC]
settings.secret = settings.inparam.concat(settings.h).concat(settings.r).concat(settings.c)
settings.public = settings.mlen
settings.constraints = [claripy.ULT(settings.mlen, 35)]
from pluginTime import TIME_STRATEGY_SHORTEST
settings.TIME_STRATEGY = TIME_STRATEGY_SHORTEST
def stateInit(startState):
    startState.memory.store(settings.pointerInparam, settings.inparam, 35)
    startState.memory.store(settings.pointerC, settings.c, 20)
    startState.memory.store(settings.pointerR, settings.r, 20)
    startState.memory.store(settings.pointerH, settings.h, 20)
    return True
settings.stateInit = stateInit
import tool

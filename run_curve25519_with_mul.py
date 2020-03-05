import settings
import claripy
settings.WARNING_ADDRESS = 0x1fcb0
settings.VERBOSE = True
settings.DEBUG = True
settings.TARGET_BINARY = "/home/stefan/Documents/Graduation/RISC-V-toolchain/riscv/Programs/WithMultiplication/Curve25519_scalarmult/Radix226/program.elf"
settings.TARGET_ADDRESS = 0x200116c4
settings.r = claripy.BVS("result", 32*8)
settings.pointerR= 100000
settings.n = claripy.BVS("n", 32*8)
settings.pointerN=110000
settings.g = claripy.BVS("g", 32*8)
settings.pointerG=120000
settings.params = [settings.pointerR, settings.pointerN, settings.pointerG]
settings.secret = settings.n.concat(settings.g).concat(settings.r)
#settings.constraints = [claripy.SLT(settings.A, 5), claripy.SGE(settings.A, 1)]
settings.skips = [(0x20012704, 0x20012e68), (0x2001419c, 0x200147a8)] 
from pluginTime import TIME_STRATEGY_SHORTEST
settings.TIME_STRATEGY = TIME_STRATEGY_SHORTEST
def stateInit(startState):
    startState.memory.store(settings.pointerR, settings.r, 32)
    startState.memory.store(settings.pointerN, settings.n, 32)
    startState.memory.store(settings.pointerG, settings.g, 32)
    return True
settings.stateInit = stateInit
import tool

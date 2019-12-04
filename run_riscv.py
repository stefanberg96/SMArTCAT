import settings
import claripy
settings.WARNING_ADDRESS = 0x1fcb0
settings.VERBOSE = True
settings.DEBUG = True
settings.TARGET_BINARY = "/home/stefan/Documents/Graduation/RISC-V-toolchain/riscv/Programs/Poly1305_onetimeauth/Radix2.26_woMultiplier/program.elf"
settings.TARGET_ADDRESS = 0x20010fec
settings.mulA = claripy.BVS("a", 32, max=2^26-1, min=0)
settings.mulB = claripy.BVS("b", 32, max=2^26-1, min=0)
settings.params = [settings.mulA, settings.mulB]
settings.secret = settings.mulA.concat(settings.mulB)
from pluginTime import TIME_STRATEGY_SHORTEST
settings.TIME_STRATEGY = TIME_STRATEGY_SHORTEST
def stateInit(startState):
    return True
settings.stateInit = stateInit
import tool

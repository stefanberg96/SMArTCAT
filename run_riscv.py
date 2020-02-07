import settings
import claripy
settings.WARNING_ADDRESS = 0x1fcb0
settings.VERBOSE = True
settings.DEBUG = True
settings.TARGET_BINARY = "/home/stefan/Documents/Graduation/RISC-V-toolchain/riscv/Programs/Poly1305_onetimeauth/Radix2.26_woMultiplier/program.elf"
settings.TARGET_ADDRESS = 0x20011dfc
settings.A = claripy.BVS('A', 32)
settings.params = [settings.A]
settings.secret = settings.A
settings.constraints = [claripy.SLT(settings.A, 5), claripy.SGE(settings.A, 1)]
from pluginTime import TIME_STRATEGY_SHORTEST
settings.TIME_STRATEGY = TIME_STRATEGY_SHORTEST
def stateInit(startState):
    return True
settings.stateInit = stateInit
import tool

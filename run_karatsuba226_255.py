import settings
import claripy
settings.WARNING_ADDRESS = 0x1fcb0
settings.VERBOSE = True
settings.DEBUG = True
settings.TARGET_BINARY = "/home/stefan/Documents/Graduation/RISC-V-toolchain/riscv/Programs/WithoutMultiplication/build/program.elf"
settings.TARGET_ADDRESS = 0x20010850
settings.mulA = claripy.BVS("a", 160)
settings.pointerA=100000
settings.pointerB=110000
settings.mulB = claripy.BVS("b", 160)
settings.params = [settings.pointerA, settings.pointerB]
settings.secret = settings.mulA.concat(settings.mulB)
from pluginTime import TIME_STRATEGY_SHORTEST
settings.TIME_STRATEGY = TIME_STRATEGY_SHORTEST
def stateInit(startState):
    startState.memory.store(settings.pointerA, settings.mulA, 20)
    startState.memory.store(settings.pointerB, settings.mulB, 20)
    return True
settings.stateInit = stateInit
import tool
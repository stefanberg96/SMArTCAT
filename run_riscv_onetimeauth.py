import settings
import claripy
settings.WARNING_ADDRESS = 0x1fcb0
settings.VERBOSE = True
settings.DEBUG = True
settings.TARGET_BINARY = "/home/stefan/Documents/Graduation/RISC-V-toolchain/riscv/Programs/Poly1305_onetimeauth/Radix2.26_woMultiplier/program.elf"
settings.TARGET_ADDRESS = 0x20010490
settings.outputBufPointer = 0x10000

settings.messagelength = 10
settings.message = claripy.BVS('m', settings.messagelength*8+8)
settings.messagePointer = 0x11000

settings.key = claripy.BVS('k', 34*8)
settings.keyPointer = 0x12000

settings.params = [settings.outputBufferPointer, settings.messagePointer, settings.messagelength , settings.key]
settings.secret = settings.message.concat(settings.key)

from pluginTime import TIME_STRATEGY_SHORTEST
settings.TIME_STRATEGY = TIME_STRATEGY_SHORTEST
def stateInit(startState):
     #TODO intialize mem
    startState.memory.store(settings.keyPointer, settings.key, 32)
    startState.memory.store(settings.messagePointer, settings.message, settings.messagelength)
    return True
settings.stateInit = stateInit
import tool

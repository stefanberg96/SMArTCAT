import settings
import claripy
settings.VERBOSE = True
settings.DEBUG = True
settings.TARGET_BINARY = "/home/stefan/rasp/arm_files/test2"
settings.TARGET_ADDRESS = 0x103d0
settings.messageA = claripy.BVS("x", 32)
settings.pointerToA = 100000
settings.pointerToB = 110000
settings.messageB = claripy.BVS("y",32)
settings.params = [settings.pointerToA, settings.pointerToB]
settings.secret = settings.messageA
settings.public = settings.messageB
from pluginTime import TIME_STRATEGY_SHORTEST_IF_NONSECRET
settings.TIME_STRATEGY = TIME_STRATEGY_SHORTEST_IF_NONSECRET
def stateInit(startState):
    startState.memory.store(settings.pointerToA, settings.messageA, 4)
    startState.memory.store(settings.pointerToB, settings.messageB, 4)
    return True
settings.stateInit = stateInit
import tool

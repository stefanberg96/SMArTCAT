import settings
import claripy
settings.WARNING_ADDRESS = 0x1fcb0
settings.VERBOSE = True
settings.DEBUG = True
settings.TARGET_BINARY = "/home/stefan/rasp/arm_files/test"
settings.TARGET_ADDRESS = 0x1051c
settings.messageA = claripy.BVS("messageA", 1024)
settings.messageB = claripy.BVS("messageB", 1024)
settings.pointerToA = 100000
settings.pointerToB = 110000
settings.params = [settings.pointerToA, settings.pointerToB]
settings.secret = settings.messageA
from pluginTime import TIME_STRATEGY_AVERAGE
settings.TIME_STRATEGY = TIME_STRATEGY_AVERAGE
#settings.PG_EXPLORE_ARGUMENTS = {"find":0x10588, "avoid":0x1058c}

def stateInit(startState):
    startState.memory.store(settings.pointerToA, settings.messageA, 128)
    startState.memory.store(settings.pointerToB, settings.messageB, 128)
    return True
settings.stateInit = stateInit
import tool

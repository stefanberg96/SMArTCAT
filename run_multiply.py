import settings
import claripy
settings.WARNING_ADDRESS = 0x1fcb0
settings.VERBOSE = True
settings.DEBUG = True
settings.TARGET_BINARY = "/home/stefan/rasp/arm_files/test"
settings.TARGET_FUNCTION = "multiply"
settings.mulA = claripy.BVS("a", 2)
settings.mulB = claripy.BVS("b", 2)
settings.params = [settings.mulA, settings.mulB]
settings.secret = settings.mulA
from pluginTime import TIME_STRATEGY_SHORTEST
settings.TIME_STRATEGY = TIME_STRATEGY_SHORTEST
def stateInit(startState):
    return True
settings.stateInit = stateInit
import tool

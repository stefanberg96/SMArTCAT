"""
This file contains the main settings used by the tool
"""
import claripy

#Analysis target:
TARGET_BINARY = ""#"testShiftedLoadARM"
TARGET_FUNCTION = ""#"fun" #(when set to empty string it will analyse main)
TARGET_ADDRESS = None

WARNING_ADDRESS = 0

#Output vex instructions:
OUTPUT_VEX = False

#Output instructions and pipeline bubbles:
VERBOSE = True

#Whether to model cache and branch-prediction-based timing channels
MODEL_CACHE_CHANNELS = False
MODEL_BRANCH_CHANNELS = True

#Default times for unmodelled instructions:
DEFAULTEXECUTIONTIME = 1
DEFAULTRESULTLATENCY = 1

#Estimated max cache-miss overhead
MAX_STORE_CACHE_MISS_SLOWDOWN = 90 #measured time by decrementing mem address by 8192 every measurement round. This doesn't affect bailout
MAX_LOAD_CACHE_MISS_SLOWDOWN = 9

#Max memory usage in GB
MAX_MEM = 13

#Concretisation strategy to handle symbolic execution time
from pluginTime import TIME_STRATEGY_SHORTEST_IF_NONSECRET
TIME_STRATEGY = TIME_STRATEGY_SHORTEST_IF_NONSECRET

from pipelineModel import LATENCY_STRATEGY_SHORTEST_IF_NONSECRET
LATENCY_STRATEGY = LATENCY_STRATEGY_SHORTEST_IF_NONSECRET


PG_EXPLORE_ARGUMENTS = {}
constraints = []

PC_ONLY = False

OUTPUT_FREQUENCY = 256

#function input parameters
public = claripy.BVS("publicArgument", 32)
secretSymbol = claripy.BVS("secretArgument", 32)
#pointerToSecret = claripy.BVS("pointerToSecret", 32)
#params = [public, secret]

key = claripy.BVS("key", 32)
#pointerToKey = claripy.BVS("pointerToKey", 32)
pointerToKey = 100512
messagelength = 4
message = claripy.BVS("message", 32)
#pointerToMessage = claripy.BVS("pointerToMessage", 32)
pointerToMessage = 110000
#outputBufferPointer = claripy.BVS("outputBufferPointer", 32)
outputBufferPointer = 101024
outputBufferLength = claripy.BVS("outputBufferLength", 32)
#noncePointer = claripy.BVS("noncePointer", 32)
#noncePointer = -300
nonce = claripy.BVS("nonce", 32)
params = [outputBufferPointer, outputBufferLength, pointerToMessage, messagelength, pointerToKey]

#List of tuples with begin address up to but not including the end addres of what to skip 
skips=[] 
secret = key

#TARGET_ADDRESS = 0x1ef2c

warning_function = None
WARNING_BEFORE = 0
WARNING_AFTER = 1
warning_moment = WARNING_BEFORE

def stateInit(startState):
    """stateInit is called before symbolic execution starts. Override it to initialize the starting state."""
    startState.memory.store(pointerToKey, key, 4)
    startState.memory.store(pointerToMessage, message, 4)
    return True

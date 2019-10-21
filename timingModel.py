from __future__ import print_function
import claripy
solver = claripy.Solver()
import angr.engines.vex.ccall as ccall
import analysisUtils as Au

import settings
    
# the branchPredictionSwitch is used to model timing differences caused by branchPredictionFails.
# note these may be hard to exploit, so by setting the switch to 0 the time caused by branch prediction fails is always set to 1.
# by not setting the switch statement maximum timing differences can be computed.
# we only do this if the branch prediction depends on a secret value by further analyzing this in the calling timeExecution.SimIRStmt_Time
#   if the time depends only on a public value we average the value (is this the best prediction strategy? minimum time is probably better in loops)
#this is hacked as a BVS 1 bit number, because booleans don't really want to work with us
#branchPredictionSwitch = claripy.BVS("branchPredictionSwitch",1)
branchSwitchInstances = {}

#similar to branchPredictionSwitch but for cache miss based attacks
cacheSwitchInstances = {}

unmodeledInstructions = set()

MEMORY_PLACEHOLDER = -2

lastCondition = [None, None, None]

cacheSwitch = True
def modelCacheMisses(solver, switch):
    if switch:
        dictionary = {}
        for k,switchInstance in cacheSwitchInstances.items():
            dictionary[(switchInstance == 0).cache_key] = None
        for k,constraint in enumerate(solver.constraints):
            solver.constraints[k] = constraint.replace_dict(dictionary)
        while None in solver.constraints:
            solver.constraints.remove(None)
        constraints = solver.constraints
        solver.__init__()
        solver.add(constraints)
    else:
        for k,switchInstance in cacheSwitchInstances.items():
            solver.add(switchInstance == 0)
    cacheSwitch = switch
    
branchSwitch = True
def modelBranchMisses(solver, switch):
    if switch:
        dictionary = {}
        for k,switchInstance in branchSwitchInstances.items():
            dictionary[(switchInstance == 0).cache_key] = None
        for k,constraint in enumerate(solver.constraints):
            solver.constraints[k] = constraint.replace_dict(dictionary)
        while None in solver.constraints:
            solver.constraints.remove(None)
        constraints = solver.constraints
        solver.__init__()
        solver.add(constraints)
    else:
        for k,switchInstance in branchSwitchInstances.items():
            solver.add(switchInstance == 0)
    cacheSwitch = switch

def computeCondition(ccode, state):
    global lastCondition
    if lastCondition[0] == ccode and lastCondition[1] == state:
        return lastCondition[2]
    else:
        cond_n_op = claripy.BVV(ccode<<4, 32)|state.regs.cc_op
        condition = ccall.armg_calculate_condition(state, cond_n_op, state.regs.cc_dep1, state.regs.cc_dep2, state.regs.cc_ndep)
        lastCondition = [ccode, state, condition[0]]
        return condition[0]
        
def violationType(insn, props): 
    """
    this function assumes the instruction contains a validation. if it does, it returns the violation type. Undefined otherwise
    """
    #if (insn.group(1)): return 1 #branch instructions.. according to capstone.CS_GRP_JUMP
    if (props.isTrueBranch()): return 1 #branch instructions.. according to capstone.CS_GRP_JUMP
    elif (insn.cc != 0 and insn.cc != 15): return 3 #there's a condition code: conditional instruction
    else:
        float = False #besides conditional instructions, floating point operations are the only T3 violation we know of in the Pi 2
        for o in insn.operands:
            if o.type == 3: #memop
                return 2
            elif o.type == 4: #fpop
                float = True
        if float: return 3
        else: return 0

#TODO low priority: return the symbol(/ symbollic expression) on which the timing depends along with the timing.
def time(props, insn, state, reg=None):
    """
    generic function to return timing for any instruction
    """
    timing = props.timeTupleTuple()
    
    if props.hasSpecialLatencyNeeds():
        specialLatency = props.specialLatency()
        if reg in specialLatency:
            timing[1] = props.specialLatency()[reg]
        elif reg == MEMORY_PLACEHOLDER:
            timing[1] = props.specialLatency().items()[0]
        else:
            timing[1] = (None, None)
            
    
    if props.isMemInsn():
        timing = [[timing[0][0],timing[0][1]],[timing[1][0],timing[1][1]]]
        if props.ldr or props.ldm or props.pop:
            timeDiff = settings.MAX_LOAD_CACHE_MISS_SLOWDOWN
        elif props.str or props.stm or props.push:
            timeDiff = settings.MAX_STORE_CACHE_MISS_SLOWDOWN
        else:
            print("unmodelled memory instruction: 0x%x: %s %s; assumed worst case cache time difference" % (insn.address, insn.mnemonic, insn.op_str))
            timeDiff = settings.MAX_STORE_CACHE_MISS_SLOWDOWN
        
        if settings.MODEL_CACHE_CHANNELS:
            cacheMissInstance = claripy.BVS("cacheMissInstance",1) #unique for this specific cache miss
            cacheSwitchInstances[cacheMissInstance.cache_key] = cacheMissInstance
            timing[0][0] = claripy.If(cacheMissInstance == 1, claripy.BVV(timing[0][0]+timeDiff, 32), claripy.BVV(timing[0][0], 32))
            #check if any of the symbols in timing are in state.se._solver.inequalSymbols, if so, create a copy for the cachemissinstance with symbolCopies and add it to 
            #state.se._solver.addConnector(cacheMissInstance)
            #state.se._solver.symbolCopies(cacheMissInstance)
            #state.se._solver.addConnector(claripy.Or(cacheMissInstance == 0, cacheMissInstance == 1))
            #state.se._solver.addConnector(claripy.Or(state.se._solver.symbolCopies(cacheMissInstance)[1] == 0, state.se._solver.symbolCopies(cacheMissInstance)[1] == 1))
    
    if props.isTrueBranch():
        #model branch predictor misses
        if insn.insn_name() == 'blx':
            flushtime = 8
        else: #instructions b and bl
            flushtime = 7
        if settings.MODEL_BRANCH_CHANNELS:
            branchMissInstance = claripy.BVS("branchMissInstance",1) #unique for this specific cache miss
            branchSwitchInstances[branchMissInstance.cache_key] = branchMissInstance
            timing = ((claripy.If(branchMissInstance == 1, claripy.BVV(timing[0][0]+flushtime, 32), claripy.BVV(timing[0][0], 32)),claripy.If(branchMissInstance == 1, claripy.BVV(timing[0][1]+flushtime, 32), claripy.BVV(timing[0][1], 32))), timing[1])
            #state.se._solver.symbolCopies(branchMissInstance)
            #state.se._solver.addConnector(claripy.Or(branchMissInstance == 0, branchMissInstance == 1))
            #state.se._solver.addConnector(claripy.Or(state.se._solver.symbolCopies(branchMissInstance)[1] == 0, state.se._solver.symbolCopies(branchMissInstance)[1] == 1))
            #timing[0][0] = claripy.If(branchMissInstance == 1, claripy.BVV(timing[0][0]+flushtime, 32), claripy.BVV(timing[0][0], 32))
            #timing[0][1] = claripy.If(branchMissInstance == 1, claripy.BVV(timing[0][1]+flushtime, 32), claripy.BVV(timing[0][1], 32))
    elif props.isEffectiveBranch():
        #model issue time / bailout increase
        timing = ((timing[0][0]+9, timing[0][1]+1),timing[1])
        #timing[0][0] += 9   #branching time
        #timing[0][1] += 1   #bailout time
    
    if timing == None:
        if props.format == None:
            unmodeledInstructions.add("%s %s" % (insn.mnemonic, insn.op_str))
        else:
            unmodeledInstructions.add(props.format)
            print("No known timing for instruction %s" % (props.format,))
        issue = settings.DEFAULTEXECUTIONTIME
        latency = settings.DEFAULTRESULTLATENCY
    elif (insn.cc != 15 and insn.cc != 0) and (Au.ASTSafeEqualsComparison(timing[0][0], timing[0][1]) or Au.ASTSafeEqualsComparison(timing[1][0], timing[1][1])): #conditional execution
        condition = computeCondition(insn.cc-1, state)
        if not Au.ASTSafeEqualsComparison(timing[0][0], timing[0][1]) and state.se.satisfiable([condition==1]):
            if state.se.satisfiable([condition!=1]):
                #Arithmetic representation of the if-statement seems a lot more efficient than using the actual if statement, probably because it can be simplified easier
                #issue = claripy.If(condition==1, claripy.BVV(timing[0][0], 32), claripy.BVV(timing[0][1], 32))
                issue = condition*claripy.BVV(timing[0][0], 32) + (1-condition)*claripy.BVV(timing[0][1], 32)
            else:
                issue = timing[0][0]
        else:
            issue = timing[0][1]
        if not Au.ASTSafeEqualsComparison(timing[1][0], timing[1][1]) and state.se.satisfiable([condition==1]):
            if state.se.satisfiable([condition!=1]):
                #latency = claripy.If(condition==1, claripy.BVV(timing[1][0], 32), claripy.BVV(timing[1][1], 32))
                latency = condition*claripy.BVV(timing[1][0], 32) + (1-condition)*claripy.BVV(timing[1][1], 32)
            else:
                latency = timing[1][0]
        else:
            latency = timing[1][1]
    else:
        issue = timing[0][0]
        latency = timing[1][0]
        
        
    return (issue, latency)

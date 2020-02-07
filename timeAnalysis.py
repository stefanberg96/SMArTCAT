from __future__ import print_function
#runs an analysis, outputs some timing information

import settings

from selfComposition import SelfComposition

import angr
import claripy
import pathTimeComparison
import analysisUtils as u
import subprocess
import store

#settings.TARGET_FUNCTION = "";
#settings.TARGET_BINARY = "testMultivariateARM"
#settings.TARGET_FUNCTION = "pinToByte"
#settings.TARGET_BINARY = "a.out"
#settings.TARGET_FUNCTION = "fun"
#settings.TARGET_BINARY = "testShiftedLoadARM"
#settings.TARGET_FUNCTION = "fun"
##targetAddress = 0x00010554 #pinToByte
#settings.TARGET_BINARY = "testMemoryARM"
##targetAddress = 0x00010584 #extractSecret
#settings.TARGET_BINARY = "MULEQtestARM"
##targetAddress = 0x000104b0 #fun

#objdump = "/usr/arm-linux-gnueabi/bin/objdump"
objdump = "/home/stefan/Documents/Graduation/RISC-V-toolchain/riscv-gnu-toolchain/build-binutils-newlib/binutils/objdump"

def step0():
    """
    preprocessing
    """
    print("\n======================= Pre-analysis ========================\n")
    print("running pre-analysis on %s; function: %s" % (settings.TARGET_BINARY, settings.TARGET_FUNCTION))
    try:
        if settings.TARGET_FUNCTION == "":
            conditionals = subprocess.check_output("%s -d %s | grep -P '\t*(eq|ne|cs|cc|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)(\.w)?\t'" % (objdump,settings.TARGET_BINARY), shell=True)
        else:
            conditionals = subprocess.check_output("%s -d %s | awk '/<%s>:/{flag=1;next}/<.*>:/{flag=0}flag'| grep -P '\t*(eq|ne|cs|cc|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)(\.w)?\t'" % (objdump, settings.TARGET_BINARY, settings.TARGET_FUNCTION), shell=True)
        
        print("(possible) conditional instructions identified (note, no jumps to other functions were followed)")
        print(conditionals)
    except:
        print("no conditional instruction identified in this instruction.")

def step1():
    """
    symbolic execution
    """
    print("\n==================== Symbolic Execution =====================\n")
    if settings.TARGET_ADDRESS == None:
        if settings.TARGET_FUNCTION != "":
            targetAddress = int(subprocess.check_output("%s -d %s | awk '/<%s>:/' | grep -o '^[0-9a-f]*'" % (objdump, settings.TARGET_BINARY, settings.TARGET_FUNCTION), shell=True), base=16)
        else: 
            #execute the main function.
            targetAddress = int(subprocess.check_output("%s -d %s | awk '/<main>:/' | grep -o '^[0-9a-f]*'" % (objdump, settings.TARGET_BINARY), shell=True), base=16)
    else:
        targetAddress = settings.TARGET_ADDRESS
    print("running simple analysis on %s" % settings.TARGET_BINARY)
    b = store.b
    global startState
    
    #startState = b.factory.call_state(u.functionAddress("pinToByte",b.filename), public, secret)
    #startState = b.factory.call_state(targetAddress, public, secret)
    #other options to try:
    #ABSTRACT_MEMORY #not sure what this does exactly but it messes things up. (for one, t2 violations at every store.
    #CONSERVATIVE_WRITE_STRATEGY  &  CONSERVATIVE_READ_STRATEGY  this combination seems to get us the furthest.
    #simuvex.o.SYMBOLIC_WRITE_ADDRESSES ineffective
    #startState = b.factory.call_state(targetAddress, public, secret)
    startState = b.factory.call_state(targetAddress, *settings.params, add_options={angr.sim_options.CONSERVATIVE_WRITE_STRATEGY, angr.sim_options.CONSERVATIVE_READ_STRATEGY})
    #startState.memory.store(pointerToSecret, secret, 4)
    settings.stateInit(startState)
    startState.meta.factory = b.factory
    startState.options.discard('OPTIMIZE_IR') #OMG make sure to keep this here or optimisation level will be overriden all the time
    tpg = b.factory.simgr(startState, save_unsat = True)
    store.tpg = tpg
    b.arch.capstone.detail=True #set this so we have access to instruction details required for our timing model
    
    #add the self-composition connectors to the self-composition solver
    startState.solver._solver.addInequalityConnector(settings.secret)
    # add constraints defined in the settings
    for con in settings.constraints:
        startState.solver._solver.add(con)
    
    import resource
    import gc
    import timingModel
    from angr.exploration_techniques import LoopSeer


    for i in range(0,10):
        try:
                if i == 0:
                    tpg.explore(**settings.PG_EXPLORE_ARGUMENTS, n=1000)
                if len(tpg.errored) > 0 or len(tpg.active) > 0:
                    tpg.run()
        except (MemoryError, resource.error):
                print("ran out of memory... freeing memory")
                if len(store.tpg.active) > 0:
                    store.tpg.active[0].state.se._solver._solver_backend.downsize()
                if 2 % 20 == 0:
                    timingModel.cacheSwitchInstances = {}
                    timingModel.branchSwitchInstances = {}
                gc.collect()
                print("continuing analysis...")

    print("\n-------------------------------------------------------------\n")
    print("Finished execution")
    step1_1(tpg.unconstrained)
    
def step1_1(pathList):
    print("identified %d distinct paths" % len(pathList))
    print("Possible timings for this code: ")
    warnLimit = False
    for k,d in enumerate(pathList):
        if not d.solver.satisfiable():
            print("path %d unsatisfiable" % (k))
        else:
            solutions = d.solver.eval_upto(d.time.totalExecutionTime,10)
            print("path %d timings: %s\t(pc-model: %s)" % (k, solutions, d.time.instructionCount))
            if len(solutions)==10:
                warnLimit = True
    if warnLimit:
        print ("No more than 10 solutions per path displayed.")
            
def step2():
    """
    minor post-processing, unused
    """
    global b
    global tpg
    global startState
    for d in tpg.deadended:
        evals = d.solver.eval_upto(settings.secret.reversed, 256)
        length = len(evals)
        if (length == 256):
            print("256 or more solutions")
        else:
            print("%d solutions" % length)
            print(evals)

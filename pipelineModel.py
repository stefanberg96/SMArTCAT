"""
This module adds timing functionality to the vex IMark statements
"""
from __future__ import print_function
import timingModel
import claripy
import capstone as cap
import analysisUtils as au
import pluginTime
from properties import Properties
capcon = cap.arm_const
import angr.engines.vex.ccall as ccall
from collections import defaultdict
import store
import os
import psutil
import angr as angr
 
from selfComposition import SelfComposition
 
import logging
l = logging.getLogger(name = "pipelineModel")

MEMORY_ADDRESSES_PER_INT = 4

REG_MAPPING = {u's7': 86, u'd19': 33, u'd8': 22, u'd9': 23, u'd6': 20, u'd7': 21, u'd4': 18, u'd5': 19, u'd2': 16, u'd3': 17, u'd0': 14, u'd1': 15, u'q1': 51, u'q0': 50, u'q3': 53, u'q2': 52, u'q5': 55, u'q4': 54, u'q7': 57, u'q6': 56, u'q9': 59, u'q8': 58, u'd30': 44, u'd31': 45, u'lr': 10, u'fpsid': 8, u'apsr_nzcv': 2, u'mvfr2': 49, u'mvfr0': 47, u'mvfr1': 48, u's19': 98, u's18': 97, u's13': 92, u's12': 91, u's11': 90, u's10': 89, u's17': 96, u's16': 95, u's15': 94, u's14': 93, u'q15': 65, u'q14': 64, u'q11': 61, u'q10': 60, u'q13': 63, u'q12': 62, u'fpinst2': 46, u'r4': 70, u'r5': 71, u'r6': 72, u'r7': 73, u'r0': 66, u'r1': 67, u'r2': 68, u'r3': 69, u'r8': 74, u'spsr': 13, u'pc': 11, u's31': 110, u's30': 109, u'd21': 35, u'fpinst': 5, u'itstate': 9, u'sp': 12, u'ip': 78, u'cpsr': 3, u'd14': 28, u'd15': 29, u'd16': 30, u'd17': 31, u'd10': 24, u'd11': 25, u'd12': 26, u'd13': 27, u's3': 82, u's2': 81, u's1': 80, u's0': 79, u'd18': 32, u's6': 85, u's5': 84, u's4': 83, u'fpscr_nzcv': 7, u'fp': 77, u'fpscr': 6, u's25': 104, u's9': 88, u's8': 87, u'fpexc': 4, u'd29': 43, u'd28': 42, u'apsr': 1, u'd20': 34, u'd23': 37, u'd22': 36, u'd25': 39, u'd24': 38, u'd27': 41, u'd26': 40, u's22': 101, u's23': 102, u's20': 99, u's21': 100, u's26': 105, u's27': 106, u's24': 103, u'sl': 76, u'sb': 75, u's28': 107, u's29': 108}

SPECIAL_REG_MAPPING = {'a1': 'r0', 'a2': 'r1', 'a3': 'r2', 'a4': 'r3',
'v1': 'r4', 'v2': 'r5', 'v3': 'r6', 'v4': 'r7', 'v5': 'r8', 'v6': 'r9', 'v7': 'r10', 'v8': 'r11', 
 'sb': 'r9', 'sl':'r10', 'fp':'r11', 'ip':'r12', 'sp':'r13', 'lr':'r14', 'pc':'r15'} #real mapping
#SPECIAL_REG_MAPPING = {'fp':11, 'sl':10, 'pc':11, 'sp':12, 'lr':10}  #capstone mapping

emptySolver = SelfComposition()

import settings

selfcompTime = 0


LATENCY_STRATEGY_SHORTEST = 0
LATENCY_STRATEGY_AVERAGE = 1
LATENCY_STRATEGY_LONGEST = 2
LATENCY_STRATEGY_NO_CHANGE = 3
LATENCY_STRATEGY_SHORTEST_IF_NONSECRET = 4
LATENCY_STRATEGY_AVERAGE_IF_NONSECRET = 5
LATENCY_STRATEGY_LONGEST_IF_NONSECRET = 6
LATENCY_STRATEGY_SHORTEST_IF_NONSECRET_MEMORY = 7
LATENCY_STRATEGY_AVERAGE_IF_NONSECRET_MEMORY = 8
LATENCY_STRATEGY_LONGEST_IF_NONSECRET_MEMORY = 9


def parseReg(reg):
    ''' returns the register number as x$reg'''
    return "x"+str(reg)

_shift = None        
noneRegInsn = None

def computeMemLocation(operand, state):
    """
    compute a memory location from a memory operand
    takes into account base and index registers, shifts, scales, and displacements
    """
    memOperand = operand.mem
    baseReg = state.meta.factory.project.arch.capstone.reg_name(memOperand.base)
    
    if baseReg == None:
        global noneRegInsn
        noneRegInsn = operand
    baseVal = state.regs.get(baseReg) if memOperand.base != 0 else 0
    return (baseVal + memOperand.disp)
    

def warningFunc(_self, props, insn, timingModel, dependencies = None):    
    #store an instruction for debugging purposes
    import store
    store.props = props
    store.insn = insn
    store.state = _self.state.copy()
    store.stmt = _self.stmt
    store.cc = timingModel.computeCondition(store.insn.cc-1, store.state)
    store.dependencies = dependencies
    print("*************************************** address found ***************************************")
    if settings.warning_function != None:
        settings.warning_function(_self.state, insn)
    
def computePipelineTime(_self, state, stmt):
    """
    This function is meant to be called in IMarkStatement._execute (it is injected there by init.py)
    """
    #print "starting new instruction"
    timeplugin = state.time #local cache seems accessible a lot faster
    if (not settings.VERBOSE) and timeplugin.instructionCount % settings.OUTPUT_FREQUENCY == 0:
        print("instruction counter at %d; address at: %x" % (timeplugin.instructionCount, stmt.addr))
    if not settings.PC_ONLY and state.solver.satisfiable():
        
        #0 instruction fetch
        project = state.meta.factory.project
        bytes = project.loader.memory.load(stmt.addr, stmt.len)
        cs = project.arch.capstone 
        z = cs.disasm(bytes, stmt.addr)
        #we're performing double disassembling because the lifter is also doing it... probably not the most efficient thing... but it doesn't seem to be a bottleneck
        insn = next(z)
        props = Properties(insn)
        
        if settings.VERBOSE:
            print("%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))

        if insn.address == settings.WARNING_ADDRESS and settings.WARNING_MOMENT == settings.WARNING_BEFORE:
            warningFunc(_self, props, insn, timingModel)
        
        registers = timeplugin.registers
        
        #1 determine dependencies of instruction and update time accordingly:
        #registers = insn.regs_access() #actually don't want to use this, might just use insn.operands and loop over it... since it containts regs and mem as well
        dependencies = [set(),set()]
        
        #maintain list of semiBypassedRegs for cleanup
        semiBypassedRegs = []
        canReceiveSemiBypass = props.canReceiveSemiBypass()

        for operand in insn.operands:
            if operand.access == cap.CS_AC_READ:
                if operand.type == cap.CS_OP_REG:
                    dependencies[0].add(operand.reg)
                    #check whether this insn can receive a semi-bypass:
                    if canReceiveSemiBypass and operand.reg in registers and not registers[operand.reg][3].resultsBypassed:
                        semiBypassedRegs.append(operand.reg)
                elif operand.type == cap.CS_OP_MEM: #TODO Think about how to do memory
                    dependencies[0].add(operand.reg) #this is the register which determines the memory location
                    memloc = computeMemLocation(operand, state)
                    dependencies[1].add(memloc)
            elif operand.access == cap.CS_AC_WRITE and operand.type == cap.CS_OP_MEM:
                dependencies[0].add(operand.reg)
                memloc = computeMemLocation(operand, state)
                dependencies[1].add(memloc)
          
        #perform semi-bypasses
        for r in semiBypassedRegs:
            registers[r][0] -= 1 #we don't care about taking into account that latency cannot be less than 1 cycle, because issue time will prevent instructions from executing too early like that
            registers[r][3].resultsBypassed = True
            
        #print "started updating time from depependencies"
                 
        #update current time to max of current time and availability of registers
        #if the instruction can dual issue as younger, immediately see whether there is a bubble or dual issuing is otherwise prevented
        timeplugin.updateTimeFromDependencies(dependencies[0], dependencies[1])
                 
        #if insn.address == settings.WARNING_ADDRESS:
        #    print dependencies
                 
        depends = []
        if props.isMemInsn():
            #remove from dependencies register values from registers BEING WRITTEN to memory: (dependencies is no longer used for other functionality after this line, so it is safe to do so)
            if props.str:
                if insn.operands[0].reg in dependencies[0]:
                    dependencies[0].remove(insn.operands[0].reg)
            depends.extend(dependencies[1]) #these are the memory addresses accessed by the instruction, self-composition can determine whether they are secret-dependent.
            for r in dependencies[0]:
                regname = state.meta.factory.project.arch.capstone.reg_name(r)
                regval = state.regs.get(regname) if insn.operands[0].reg != 0 else 0
                depends.append(regval)
                #print "regname: %s" % regname
                #print "regval: %s" % (regval,)
        #TODO if conditional branch add the value of the register to the depends
        if props.isTrueBranch():
            for r in dependencies[0]:
                regname = state.meta.factory.project.arch.capstone.reg_name(r)
                regval = state.regs.get(regname) if insn.operands[0].reg != 0 else 0
                depends.append(regval)
        
        #2 get issuing time and result latencies for this instruction
        #TODO
        timing = timingModel.time(props, insn, state)
        
        #the strategyEffect switch tells whether we should follow a concretization strategy for latency on the current run.
        strategyEffect = settings.LATENCY_STRATEGY < 3 #initialy set strategyEffect on True _only_ if we should always concretize latency
        def getLatency(reg=None):
            """
            gets actually latency from above timing variable or from a new register-based latency fetch for certain instructions.
            """
            result = timing[1]

            if type(result) == claripy.ast.bv.BV:
                if strategyEffect:
                    solverCopy = state.solver._stored_solver.branch()
                    if settings.LATENCY_STRATEGY == LATENCY_STRATEGY_SHORTEST or settings.LATENCY_STRATEGY == LATENCY_STRATEGY_SHORTEST_IF_NONSECRET or settings.LATENCY_STRATEGY == LATENCY_STRATEGY_SHORTEST_IF_NONSECRET_MEMORY:
                        result = solverCopy.min(result)
                    elif settings.LATENCY_STRATEGY == LATENCY_STRATEGY_AVERAGE or settings.LATENCY_STRATEGY == LATENCY_STRATEGY_AVERAGE_IF_NONSECRET or settings.LATENCY_STRATEGY == LATENCY_STRATEGY_AVERAGE_IF_NONSECRET_MEMORY:
                        result = (solverCopy.min(result) + solverCopy.max(result))/2
                    elif settings.LATENCY_STRATEGY == LATENCY_STRATEGY_LONGEST or settings.LATENCY_STRATEGY == LATENCY_STRATEGY_LONGEST_IF_NONSECRET or settings.LATENCY_STRATEGY == LATENCY_STRATEGY_LONGEST_IF_NONSECRET_MEMORY: 
                        result = solverCopy.max(result)
                else:
                    result = claripy.backends.z3.simplify(result)

            if isinstance(result, float) and  result.is_integer():
                 return int(result)
            return result
            
        #3 perform self-composition to determine potential channels in result latency
        channelInstruction = None
       
        #if insn.address == settings.WARNING_ADDRESS:
            #print "determining latency differences"
       
        dependsOnSecret = False
        for operand in insn.operands:
            if operand.access == cap.CS_AC_WRITE:
                resultLatency = getLatency(operand)
                
                #perform self-composition to check if resultLatency depends on the secret
                if type(resultLatency) == claripy.ast.bv.BV and resultLatency.symbolic and emptySolver.hasMultipleSolutions(resultLatency) and state.solver._stored_solver.proofInequalityPossible(resultLatency):
                    dependsOnSecret = True
                    
        if dependsOnSecret and len(depends) > 0:
            trueDepends = False
            for dependency in depends: #determine based on dependencies whether inequality is really possible. Actually this isn't correct, we only need 1 dependency which allows it!!
                #print "testing dependency:"
                #print dependency
                if not (type(dependency) == claripy.ast.bv.BV and resultLatency.symbolic and emptySolver.hasMultipleSolutions(dependency) and state.solver._stored_solver.proofInequalityPossible(dependency)):
                    trueDepends = True
            dependsOnSecret = trueDepends
        if dependsOnSecret:
            channelInstruction = (insn.mnemonic, insn.address)
        elif settings.LATENCY_STRATEGY >= 4:    #under the right circumstances, turn on effects of latency concretization strategy
                strategyEffect = settings.LATENCY_STRATEGY <= 6 or props.isMemInsn()
                
        #print "done updating time from dependencies"
                
        #4 update register and memory availability time
        writtenRegs = []
        for operand in insn.operands:
            if operand.access == cap.CS_AC_WRITE:
                if operand.type == cap.CS_OP_REG:
                    latencyReg = getLatency(operand.reg)
                    latencyEntry = [latencyReg + timeplugin.totalExecutionTime, channelInstruction, insn, props]
                    registers[operand.reg] = latencyEntry
                    writtenRegs.append(operand.reg)
                elif operand.type == cap.CS_OP_MEM:
                    memloc = computeMemLocation(operand, state)
                    latencyEntry = [getLatency(timingModel.MEMORY_PLACEHOLDER) + timeplugin.totalExecutionTime, channelInstruction, insn, props]
                    timeplugin.memory[memloc] = latencyEntry
                    
        #print "starting counttime update"
        
        
        #5 update current time
        violation = timeplugin.countTime(timing[0], compositionCheck=insn, props=props, dependencies=depends)
        
        #6 roundup
        if violation:
            store.violations.append(("%s, @ 0x%x" % (insn.mnemonic, insn.address), {'stmt': _self, 'state':state.copy(), 'props':props, 'insn':insn, 'timingModel':timingModel, 'dependencies':depends}))
        
        if insn.address == settings.WARNING_ADDRESS and settings.WARNING_MOMENT == settings.WARNING_AFTER:
            warningFunc(_self, props, insn, timingModel, depends)
        
        timeplugin.lastInsn = (insn, format)
        
        
        #7 cleanup
        for r in semiBypassedRegs: #cleanup latency of semi bypassed registers
            if r not in writtenRegs:
                registers[r][0] += 1
                
    timeplugin.instructionCount += 1
    #print "finished instruction"

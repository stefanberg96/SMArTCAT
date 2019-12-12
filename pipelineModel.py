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
    if reg in SPECIAL_REG_MAPPING:
        return SPECIAL_REG_MAPPING[reg]
    elif reg != None:
        return reg#.encode('ascii', 'ignore')
    else:
        print("Tried to parse None reg")


_shift = None        
noneRegInsn = None
def computeMultiMemLocs(insn, state):
    """computes a list of memory locations from an LDM or STM instruction"""
    locationCount = len(insn.operands)
    if insn.insn_name() == "pop" or insn.insn_name() == "push":
        locationCount += 1
        baseVal = state.regs.get('sp')
    else:
        theRegister = insn.operands[0].reg              #
        if theRegister == None:                         #   not sure if this is the right approach
            theRegister = insn.operands[0].mem.base     #
        baseReg = state.meta.factory._project.arch.capstone.reg_name(theRegister)
        baseVal = state.regs.get(parseReg(baseReg)) if insn.operands[0].reg != 0 else 0
    if insn.insn_name() in ["stmib", "stm", "ldmib", "ldm", "pop"]:
        step = 1    #increment
    else:
        step = -1   #decrement
    if insn.insn_name() in ["stmib", "ldmib", "stmdb", "ldmdb", "push"]:
        start = 1
    else:
        start = 0
    addresses = []
    for i in range(0,locationCount):
        address = baseVal+ (start*step + i*step)*MEMORY_ADDRESSES_PER_INT
        addresses.append(address)
    return addresses

def computeMemLocation(operand, state):
    """
    compute a memory location from a memory operand
    takes into account base and index registers, shifts, scales, and displacements
    """
    memOperand = operand.mem
    baseReg = state.meta.factory.project.arch.capstone.reg_name(memOperand.base)
    indexReg = state.meta.factory.project.arch.capstone.reg_name(memOperand.index)
    
    if indexReg == None or baseReg == None:
        global noneRegInsn
        noneRegInsn = operand
    baseVal = state.regs.get(parseReg(baseReg)) if memOperand.base != 0 else 0
    indexVal = state.regs.get(parseReg(indexReg)) if memOperand.index != 0 else 0
    if memOperand.lshift != 0:
        if index != 0:
            indexVal <<= memOperand.lshift
        else:
            baseVal <<= memOperand.lshift
    elif operand.shift != None and operand.shift.type != 0:
        global _shift
        _shift = operand.shift
        if operand.shift.type == capcon.ARM_SFT_ASR:
            indexVal = indexVal.__rshift__(operand.shift.value)
        elif operand.shift.type == capcon.ARM_SFT_LSL:
            indexVal = indexVal.__lshift__(operand.shift.value)
        elif operand.shift.type == capcon.ARM_SFT_LSR:
            indexVal = claripy.LShR(indexVal,operand.shift.value)
        elif operand.shift.type == capcon.ARM_SFT_ROR:
            indexVal = indexVal.__ror__(operand.shift.value)
        elif operand.shift.type == capcon.ARM_SFT_RRX:
            carryflag = ccall.armg_calculate_flag_c(state, state.regs.cc_op, state.regs.cc_dep1, state.regs.cc_dep2, state.regs.cc_ndep)
            indexVal = carryflag[0][0].concat(indexVal[31:1])
        else:
            print("Warning, register based register shift not modelled")
            
    if operand.subtracted:
        index = -index
    return (baseVal + indexVal*memOperand.scale + memOperand.disp)
    

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
        cs = project.arch.capstone if stmt.delta == 0 else project.arch.capstone_thumb
        
        #we're performing double disassembling because the lifter is also doing it... probably not the most efficient thing... but it doesn't seem to be a bottleneck
        insn = next(cs.disasm(bytes, stmt.addr))
        #props = Properties(insn)
        
        if settings.VERBOSE:
            print("%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))
        return
        if insn.address == settings.WARNING_ADDRESS and settings.WARNING_MOMENT == settings.WARNING_BEFORE:
            warningFunc(_self, props, insn, timingModel)
        
        registers = timeplugin.registers
        
        #1 determine dependencies of instruction and update time accordingly:
        #registers = insn.regs_access() #actually don't want to use this, might just use insn.operands and loop over it... since it containts regs and mem as well
        dependencies = [set(),set()]
        
        #Manage accumulator register:
        accReg = props.accumulatorReg()
            
        #decrease timing for late regs and increase for early regs. (only for this instruction, we correct this at the end of this instruction)
        altRegTimings = props.altRegTimings()
        for r in altRegTimings:
            if r[0] in registers: #If the register wasn't in the plugin's registers yet, there's no need to decrement time
                registers[r[0]][0] -= r[1]
            
        canDualIssueAsYounger = props.canDualIssueAsYounger()
            
        #maintain list of semiBypassedRegs for cleanup
        semiBypassedRegs = []
        canReceiveSemiBypass = props.canReceiveSemiBypass()
            
        for operand in insn.operands:
            if operand.access == cap.CS_AC_READ:
                if operand.type == cap.CS_OP_REG:
                    if not (operand.reg == accReg and registers[accReg][3].canForwardToAccumulator() and not registers[accReg][3].isRdHi(operand.reg)): #in case of an accumulator reg, just skip the register
                        if (operand.reg == accReg and registers[accReg][3].canForwardToAccumulator()): #it is actually an accumulator reg but the register was written by a RdHi, so implement half-bypass by subtracting 1 from reg
                            registers[operand.reg][0] -= 1
                        dependencies[0].add(operand.reg)
                        #check whether this insn can receive a semi-bypass:
                        if canReceiveSemiBypass and operand.reg in registers and not registers[operand.reg][3].resultsBypassed:
                            semiBypassedRegs.append(operand.reg)
                    #check whether can dual issue with previous instruction
                    if canDualIssueAsYounger and operand.reg in registers and registers[operand.reg][2] == timeplugin.lastInsn[0]:
                        canDualIssueAsYounger = False #if this instruction depends on the previous instruction, it cannot dual issue with it
                elif operand.type == cap.CS_OP_MEM:
                    dependencies[0].add(operand.reg) #this is the register which determines the memory location
                    if (operand.mem.index != 0):
                        dependencies[0].add(operand.mem.index) #this is the register which determines the memory location
                    memloc = computeMemLocation(operand, state)
                    dependencies[1].add(memloc)
                    if operand.mem.lshift != 0: #if shift and register already in timeplugin
                        if operand.mem.index == 0:  #there's no index register, shift is applied to base reg:
                            if operand.reg in registers:
                                registers[operand.reg][0] += 1
                        elif operand.mem.index in registers: #shift is applied to index reg:
                                registers[operand.mem.index][0] += 1
            elif operand.access == cap.CS_AC_WRITE and operand.type == cap.CS_OP_MEM:
                dependencies[0].add(operand.reg)
                if (operand.mem.index != 0):
                    dependencies[0].add(operand.mem.index) #this is the register which determines the memory location
                memloc = computeMemLocation(operand, state)
                dependencies[1].add(memloc)
                if operand.mem.lshift != 0: #if shift and register already in timeplugin
                    if operand.mem.index == 0:  #there's no index register, shift is applied to base reg:
                        if operand.reg in registers:
                            registers[operand.reg][0] += 1
                    elif operand.mem.index in registers: #shift is applied to index reg:
                            registers[operand.mem.index][0] += 1
                                
          
        #add memory address list for multi mem access:
        if props.stm or props.ldm or props.pop or props.push:
            dependencies = (dependencies[0], dependencies[1].union(set(computeMultiMemLocs(insn, state))))
            if props.pop or props.push:
                dependencies[0].add(REG_MAPPING['sp']) #add sp as pop and push depend on it
            
        #perform semi-bypasses
        for r in semiBypassedRegs:
            registers[r][0] -= 1 #we don't care about taking into account that latency cannot be less than 1 cycle, because issue time will prevent instructions from executing too early like that
            registers[r][3].resultsBypassed = True
            
        #add implicitly read registers to dependencies
        for reg in insn.regs_read:
            dependencies[0].add(reg)
                 
        #add flag registers to dependencies
        if insn.cc != 0 and insn.cc != 15:
            dependencies[0].add(pluginTime.FLAGS_REGISTER)
                 
                 
        #print "started updating time from depependencies"
                 
        #update current time to max of current time and availability of registers
        #if the instruction can dual issue as younger, immediately see whether there is a bubble or dual issuing is otherwise prevented
        (bubble, dualPrevented) = timeplugin.updateTimeFromDependencies(dependencies[0], dependencies[1], canDualIssueAsYounger)
                 
        #if insn.address == settings.WARNING_ADDRESS:
        #    print dependencies
                 
        depends = []
        if props.isMemInsn():
            #remove from dependencies register values from registers BEING WRITTEN to memory: (dependencies is no longer used for other functionality after this line, so it is safe to do so)
            if props.str:
                if insn.operands[0].reg in dependencies[0]:
                    dependencies[0].remove(insn.operands[0].reg)
                elif insn.insn_name() == "strex" and insn.operands[1].reg in dependencies[0]:
                    dependencies[0].remove(insn.operands[1].reg)
            if props.stm:   #somehow, registers in register list for push instruction don't have a acces type read, but acces type value 3, which doesn't exist. long story sthort: push doesn't have to be modelled
                for i in range(1,len(insn.operands)):
                    if insn.operands[i].reg in dependencies[0]:
                        dependencies[0].remove(insn.operands[i].reg)
                    #else:
                    #    print "warning, reg not found in dependencies list!"
                    #    print dependencies[0]
                    #    print insn.operands[i].reg
            depends.extend(dependencies[1]) #these are the memory addresses accessed by the instruction, self-composition can determine whether they are secret-dependent.
            for r in dependencies[0]:
                if r != -1:
                    regname = state.meta.factory.project.arch.capstone.reg_name(r)
                    regval = state.regs.get(parseReg(regname)) if insn.operands[0].reg != 0 else 0
                else:
                    #add flag register dependency:
                    regval = timingModel.computeCondition(insn.cc-1, state)
                depends.append(regval)
                #print "regname: %s" % regname
                #print "regval: %s" % (regval,)
        if props.isTrueBranch():
            if insn.insn_name() == "blx":
                for r in dependencies[0]:
                    if r != -1:
                        regname = state.meta.factory.project.arch.capstone.reg_name(r)
                        regval = state.regs.get(parseReg(regname)) if insn.operands[0].reg != 0 else 0
                    else:
                        #add flag register dependency:
                        regval = timingModel.computeCondition(insn.cc-1, state)
                    depends.append(regval)
            else:
                depends.append(pluginTime.FLAGS_REGISTER) #b and bl are true branches iff they are conditional, which creates the only dependency. flags register is already in dependencies[0] for blx
        
        if canDualIssueAsYounger: #nothing has yet prevented this instruction from dual issuing
            #we can dual issue if there was no pipeline dualPrevented and the last instruction can dual issue as older.
            dualIssue = claripy.And(claripy.Not(dualPrevented), timeplugin.canLastInsnDualWithYounger)
            #if we dual issue, we don't increment the time, otherwise we do
            if state.solver.satisfiable([dualIssue]):
                if state.solver.satisfiable([claripy.Not(dualIssue)]):
                    #symbolically dual issue
                    dualLatencyCompensation = claripy.If(dualIssue, claripy.BVV(1, 32), claripy.BVV(0, 32))
                else:
                    #always dual issue
                    dualLatencyCompensation = 1
            else:
                #never dual issue
                dualLatencyCompensation = 0
        else:
            #never dual issue
            dualLatencyCompensation = 0
        
        #2 get issuing time and result latencies for this instruction
        timing = timingModel.time(props, insn, state)
        
        #the strategyEffect switch tells whether we should follow a concretization strategy for latency on the current run.
        strategyEffect = settings.LATENCY_STRATEGY < 3 #initialy set strategyEffect on True _only_ if we should always concretize latency
        def getLatency(reg=None):
            """
            gets actually latency from above timing variable or from a new register-based latency fetch for certain instructions.
            """
            result = None
            if props.hasSpecialLatencyNeeds():
                lattiming = timingModel.time(props, insn, state, reg)
                #check if there is a special timing case for the flag register, otherwise return issue time:
                if reg == pluginTime.FLAGS_REGISTER and lattiming[1] == None:
                    result = lattiming[0]
            else:
                lattiming = timing
            if result == None:
                if reg == pluginTime.FLAGS_REGISTER:
                    result = lattiming[0] #flags register is updated at issue time
                else:
                    result = lattiming[1]
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
            result =  result-dualLatencyCompensation
            if isinstance(result, float) and  result.is_integer():
                 return int(result)
            return result
            
        #3 perform self-composition to determine potential channels in result latency
        channelInstruction = None
       
        #if insn.address == settings.WARNING_ADDRESS:
            #print "determining latency differences"
       
        dependsOnSecret = False
        for r in insn.regs_access()[1]:
            resultLatency = getLatency(r)
            
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
                    latencyEntry = [getLatency(operand.reg) + timeplugin.totalExecutionTime, channelInstruction, insn, props]
                    if insn.writeback and operand == insn.operands[0] and operand.reg in registers: #the writeback availability relies on base address availability
                        alternativeTimeAvailability = 0
                        for r in altRegTimings: #determine whether the timing was changed (it probably was because this entire scenario is written for writeback registers)
                            if r[0] == operand.reg:
                                alternativeTimeAvailability = r[1]  #relative time offset
                                break
                        latency = au.symMax(latencyEntry[0], registers[operand.reg][0]+1+alternativeTimeAvailability, state.solver._solver)
                        writebackEntry = [latency, latencyEntry[1], latencyEntry[2], latencyEntry[3]]
                        registers[operand.reg] = writebackEntry
                        writtenRegs.append(operand.reg)
                    else:
                        registers[operand.reg] = latencyEntry
                        writtenRegs.append(operand.reg)
                elif operand.type == cap.CS_OP_MEM:
                    memloc = computeMemLocation(operand, state)
                    latencyEntry = [getLatency(timingModel.MEMORY_PLACEHOLDER) + timeplugin.totalExecutionTime, channelInstruction, insn, props]
                    timeplugin.memory[memloc] = latencyEntry
                    
        #writes to implicit registers:
        for r in insn.regs_write:
            latencyEntry = [getLatency(r) + timeplugin.totalExecutionTime, channelInstruction, insn, props]
            registers[r] = latencyEntry
            writtenRegs.append(r)
        
        #writes to flag registers:
        #(virtually available 1 cycle earlier than latency)
        if insn.update_flags != 0:
            latencyEntry = [getLatency(pluginTime.FLAGS_REGISTER) + timeplugin.totalExecutionTime, channelInstruction, insn, props]
            registers[pluginTime.FLAGS_REGISTER] = latencyEntry
            writtenRegs.append(pluginTime.FLAGS_REGISTER)
        
        #print "starting counttime update"
        
        
        #5 update current time
        if canDualIssueAsYounger: #nothing has yet prevented this instruction from dual issuing
            #if we dual issue, we don't increment the time, otherwise we do
            if state.solver.satisfiable([dualIssue]):
                if state.solver.satisfiable([claripy.Not(dualIssue)]):
                    possibleDualIssueTime = claripy.If(dualIssue, claripy.BVV(0, 32), timing[0])    #symbolic dual issue
                    timeplugin.canLastInsnDualWithYounger = claripy.Not(dualIssue)
                    timeplugin.didLastInsnDualIssue = dualIssue
                else:
                    possibleDualIssueTime = claripy.BVV(0, 32)  #always dual issue
                    timeplugin.canLastInsnDualWithYounger = claripy.false
                    timeplugin.didLastInsnDualIssue = claripy.true
            else:
                possibleDualIssueTime = timing[0] #don't dual issue
                timeplugin.canLastInsnDualWithYounger = claripy.true
                timeplugin.didLastInsnDualIssue = claripy.false
                
            violation = timeplugin.countTime(possibleDualIssueTime, compositionCheck=insn, props=props, dependencies=depends)
            #if we didn't dual issue now, that means this instruction is available to dual issue as older with the next instruction (since all instructions which can dual issue as younger can also dual issue as older)
        else:
            #no dual issue possible, so count the time and set whether this instruction can dual issue as older for the following instruction
            violation = timeplugin.countTime(timing[0], compositionCheck=insn, props=props, dependencies=depends)
            if props.canDualIssueAsOlder():
                timeplugin.canLastInsnDualWithYounger = claripy.true
            else:
                timeplugin.canLastInsnDualWithYounger = claripy.false
            timeplugin.didLastInsnDualIssue = claripy.false
        
        
        #6 roundup
        if violation:
            store.violations.append(("%s, @ 0x%x" % (insn.mnemonic, insn.address), {'stmt': _self, 'state':state.copy(), 'props':props, 'insn':insn, 'timingModel':timingModel, 'dependencies':depends}))
        
        if insn.address == settings.WARNING_ADDRESS and settings.WARNING_MOMENT == settings.WARNING_AFTER:
            warningFunc(_self, props, insn, timingModel, depends)
        
        timeplugin.lastInsn = (insn, format)
        
        
        #7 cleanup
        for r in altRegTimings: #cleanup early and late regs latency
            if r[0] in registers and r[0] not in writtenRegs:
                registers[r[0]][0] += r[1]
            
        for r in semiBypassedRegs: #cleanup latency of semi bypassed registers
            if r not in writtenRegs:
                registers[r][0] += 1
                
    timeplugin.instructionCount += 1
    #print "finished instruction"

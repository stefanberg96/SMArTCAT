import claripy
solver = claripy.Solver()
import simuvex.engines.vex.ccall as ccall

# the branchPredictionSwitch is used to model timing differences caused by branchPredictionFails.
# note these may be hard to exploit, so by setting the switch to 0 the time caused by branch prediction fails is always set to 1.
# by not setting the switch statement maximum timing differences can be computed.
# we only do this if the branch prediction depends on a secret value by further analyzing this in the calling timeExecution.SimIRStmt_Time
#   if the time depends only on a public value we average the value (is this the best prediction strategy? minimum time is probably better in loops)
#this is hacked as a BVS 1 bit number, because booleans don't really want to work with us
branchPredictionSwitch = claripy.BVS("branchPredictionSwitch",1)

#similar to branchPredictionSwitch but for cache miss based attacks
cacheMissSwitch = claripy.BVS("cacheMissSwitch",1)

unmodeledInstructions = set()

DEFAULTEXECUTIONTIME = 1
DEFAULTRESULTLATENCY = 1

DEFAULT_MEM_WRITE_LATENCY = 10
DEFAULT_MEM_LOAD_LATENCY = 5

ss = None

def computeCondition(ccode, state):
    import timeAnalysis as ta
    cond_n_op = claripy.BVV(ccode<<4, 32)|state.regs.cc_op
    condition = ccall.armg_calculate_condition(state, cond_n_op, state.regs.cc_dep1, state.regs.cc_dep2, state.regs.cc_ndep)
    global ss
    ss = state.copy()
    return condition[0]
        
#TODO: return the symbol on which the timing depends along with the timing.
#currently return just timing, change that to a tuple ? alternatively: add an extra function
class TimingModel(object):
    """
    The TimingModel contains function which describe timing behavior for instructions.
    should call static timing() for timing info
    
    functions return a tuple of (issuing time, result latency)
    they are ints or symbolic expressions.
    """
    
    
    #we use a generic timing depending on the instruction type.
    #0: default, standard instruction
    #1: branch (depending on secret or nah?)
    #2: memory load (not necessarily depending on secret)
    #3: floating point instruction
    class InstType(object):
        DEFAULT = 0
        BRANCH = 1  #conditional branches only? TODO: what to do with branches to dynamic addresses
        MEMOP = 2
        FLOATOP = 3
        instructions = {}
        #"ble": BRANCH, "bgt": BRANCH, "beq": BRANCH,
        #"ldr": MEMOP, "str": MEMOP}
    
    #TODO: create a function to symbolically express conditions depending on the status flags
    
    @staticmethod
    def violationType(insn): 
        """
        this function assumes the instruction contains a validation. if it does, it returns the violation type. Undefined otherwise
        """
        if (insn.group(1)): return 1 #branch instructions.. according to capstone.CS_GRP_JUMP
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
    
    @staticmethod
    def time(insn, state):
        """
        generic function to return timing for any instruction
        """
        if insn.insn_name != insn.mnemonic and TimingModel.__dict__.__contains__(insn.mnemonic):
            #there is a specific function for the given instruction, ignore conditional execution and such
            return TimingModel.__dict__[insn.insn_name()](insn, state)
        else:
            #perform core timing
            coreTiming = TimingModel.timeCoreInsn(insn, state)
            
            result = coreTiming
            
            #if the instruction is conditional and result latency is over 2 cycles.. destination registers will be available after 2 cycles if instruction isn't actually executed
            if (insn.cc != 15 and insn.cc != 0) and state.satisfiable(extra_constraints=[coreTiming[1]>2]):
                condition = computeCondition(insn.cc-1, state)
                result = (coreTiming[0], claripy.If(condition==1, coreTiming[1], claripy.BVV(2,32)))
                
            return result
        
    @staticmethod
    def timeCoreInsn(insn, state):
        if TimingModel.__dict__.__contains__(insn.insn_name()):
            #there is a specific function for the given instruction
            return TimingModel.__dict__[insn.insn_name()](insn, state)
        else:
            InstType = TimingModel.InstType
            
            if InstType.instructions.__contains__(insn.insn_name()):
                timingType = InstType.instructions[insn.insn_name()]
                raise NotImplementendError("this instruction wasn't handled even though it should, according to timingModel InstType")
            else:
                #timingType = InstType.DEFAULT
                unmodeledInstructions.add(insn.insn_name())
                return (DEFAULTEXECUTIONTIME,DEFAULTRESULTLATENCY)
                
                
            return (DEFAULTEXECUTIONTIME,DEFAULTRESULTLATENCY)
            
    def mul(insn, state):
        return (1,3)
        
    def ldr(insn, state):
        return (1,DEFAULT_MEM_LOAD_LATENCY)
        
    def str(insn, state):
        return (1,DEFAULT_MEM_WRITE_LATENCY)
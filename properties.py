from __future__ import print_function
import capstone as cap
import capstone.arm_const as capcon

import pipelineModel

class Properties():
    """instruction properties"""
    def __init__(self, insn):
        self.insn = insn
        self.setOperandsAccessType()
        self.resultsBypassed = False
        self.ldr = "ldr" in self.insn.insn_name() 
        self.str = "str" in self.insn.insn_name()
        self.issueTimeSet = False
        self.latencyComputed = False
        self.timeTupleComputed = False
        

    def setOperandsAccessType(self):
        operandtypes=[w,r,r]
        if self.insn.mnemonic in operandtypes_branch:
            operandtypes = operandtypes_branch[self.insn.mnemonic]
        elif self.insn.mnemonic in operandtypes_jump:
            operandtypes = operandtypes_jump[self.insn.mnemonic]
        elif self.insn.mnemonic in operandtypes_load:
            operandtypes = operandtypes_load[self.insn.mnemonic]
        elif self.insn.mnemonic in operandtypes_store:
            operandtypes = operandtypes_store[self.insn.mnemonic]
        elif self.insn.mnemonic in operandtypes_non_default[self.insn.mnemonic]:
            operandtypes = operandtypes_non_default[self.insn.mnemonic]

        if len(self.insn.operands) != len((operandtypes)):
            print("Warning operands length don't match on %s", self.insn.mnemonic)
        
        for i in range(0, len(self.insn.operands)):
            self.insn.operands[i].access = operandtypes[i]
        

    def isTrueBranch(self):
        #these are only true branches if they are conditional, otherwise they are jumps
        return self.insn.mnemonic in operandtypes_branch
        #note: we don't model bx as a true branch. we can't explain how the brain predictor behaves on it
    
    def timeTupleTuple(self):
        """
            returns (issue(t/f), latency(t/f))
            latency only applies for instructions with standard latency. if hasSpecialLatencyNeeds() is true, the latency won't be correct for all writes. Use specialLatency() to find latency for different writes
            NOTE: only relies on issueTime() for memery operations
        """
        if not self.timeTupleComputed:
            if self.hasSpecialLatencyNeeds():
                issueTiming = self.issueTime()
                result = [(issueTiming, issueTiming), None] #none because hasspecialneeds!
            elif self.format in simpleTiming:
                issueTiming = simpleTiming[self.format][0]
                if issueTiming == 0:
                    issueTiming = 1
                latencyTiming = simpleTiming[self.format][0]
                result = ((issueTiming, issueTiming), (latencyTiming, latencyTiming))
            elif self.str: 
                issueTiming = self.issueTime()
                latency = issueTiming+1
                result = ((issueTiming,issueTiming), (latency,latency))
            else:
                result = None
            self.timeTuple = result
            self.timeTupleComputed = True
        return self.timeTuple
     
    def issueTime(self):
        if not self.issueTimeSet:
            if self.isMemInsn():
                if (self.ldr or self.str):
                    result = 1
                    if self.insn.operands[1].subtracted or (self.insn.operands[1].shift.type != capcon.ARM_SFT_LSL and self.insn.operands[1].shift.type != 0):
                        result += 2
                else:
                    print ("unmodelled issue time for memory operation %s" % self.insn.mnemonic)
            elif self.format in simpleTiming:
                time = simpleTiming[self.format][0]
                if time == 0:
                    time == 1
                result = time
            self.issueTiming = result
            self.issueTimeSet = True
        return self.issueTiming
        
        
    def isMemInsn(self):
        """
            returns whether this is a memory instruction (load or store)
        """
        return self.ldr or self.str 
        
    def canReceiveSemiBypass(self):
        """
            These instructions have "semi" bypasses (if they are not dual-issued of course) which means they can remove 1 cycle from result latency they depend on.
        """
        return self.insn.insn_name() in hasSimpleBypassList
        
hasSimpleBypassList = ["mov", "add", "and", "sub", "cmp", "adc", "eor", "rsb", "sbc", "rsc", "orr", "bic", "mvn", "clz", "uxtb", "sxtb", "uxth", "sxth", "usub8", "ssub8", "usub16", "ssub16", "uadd8", "sadd8", "uadd16", "sadd16", "uhadd8", "shadd8", "uhadd16", "shadd16", "uhsub8", "shsub8", "uhsub16", "shsub16", "qsax", "usax", "ssax", "uhsax", "shsax", "uqsax", "qasx", "uhasx", "uasx", "uqasx", "shasx", "sasx", "uqadd8", "qadd8", "uqadd16", "qadd16", "qadd", "uqsub8", "qsub8", "uqsub16", "qsub16", "qsub", "rsb", "sel", "usat", "usat16", "ssat", "ssat16", "cmn", "tst", "teq"]
 
        
#issue / latency
simpleTiming = {'mov<c> <rd>, #<const>': (0, 1), 'mov<c> <rd>, <rm>': (0, 1), 'cmp<c> <rn>, #<const>': (0, 0), 'cmp<c> <rn>, <rm>': (1, 1), 'cmp<c> <rn>, <rm>, <type> <rs>': (1, 1), 'cmp<c> <rn>, <rm>, <shift>': (1, 1), 'add<c> <rd>, sp, <rm>, <shift>': (1, 2), 'add<c> <rd>, sp, <rm>': (1, 1), 'add<c> <rd>, <rn>, <rm>, <type> <rs>': (1, 1), 'add<c> <rd>, <rn>, #<const>': (0, 1), 'add<c> <rd>, <rn>, <rm>, <shift>': (1, 1), 'add<c> <rd>, <rn>, <rm>': (1, 1), 'pop<c> <registers>': (2, 2), 'rev16<c> <rd>, <rm>': (1, 2), 'uhsub16<c> <rd>, <rn>, <rm>': (1, 1), 'tst<c> <rn>, <rm>': (1, 1), 'eor<c> <rd>, <rn>, #<const>': (0, 1), 'cmn<c> <rn>, #<const>': (0, 0), 'subs <rd>, <rn>, <rm>, <type> <rs>': (1, 1), 'orr<c> <rd>, <rn>, <rm>': (1, 1), 'rrx<c> <rd>, <rm>': (1, 2), 'cmn<c> <rn>, <rm>, <shift>': (1, 1), 'orrs <rd>, <rn>, <rm>, <shift>': (1, 1), 'sel<c> <rd>, <rn>, <rm>': (1, 1), 'orrs <rd>, <rn>, <rm>, <type> <rs>': (1, 1), 'ssat16<c> <rd>, #<imm>, <rn>': (1, 1), 'ror<c> <rd>, <rn>, <rm>': (1, 2), 'sbcs <rd>, <rn>, <rm>, <type> <rs>': (1, 1), 'rrxs <rd>, <rm>': (1, 2), 'teq<c> <rn>, <rm>': (1, 1), 'pkhbt<c> <rd>, <rn>, <rm>, lsl #<imm>': (1, 1), 'ssub16<c> <rd>, <rn>, <rm>': (1, 1), 'sbc<c> <rd>, <rn>, <rm>, <type> <rs>': (1, 1), 'uxth<c> <rd>, <rm>, <rotation>': (0, 1), 'cmn<c> <rn>, <rm>': (1, 1), 'sbc<c> <rd>, <rn>, <rm>': (1, 1), 'sxtab16<c> <rd>, <rn>, <rm>': (1, 1), 'adc<c> <rd>, <rn>, #<const>': (1, 1), 'mlas <rd>, <rn>, <rm>, <ra>': (1, 3), 'usat16<c> <rd>, #<imm>, <rn>': (1, 1), 'uhasx<c> <rd>, <rn>, <rm>': (1, 1), 'usat<c> <rd>, #<imm>, <rn>': (1, 1), 'adc<c> <rd>, <rn>, <rm>, <type> <rs>': (1, 1), 'asr<c> <rd>, <rn>, <rm>': (1, 2), 'sub<c> <rd>, <rn>, <rm>': (1, 1), 'mvn<c> <rd>, <rm>, <shift>': (1, 2), 'and<c> <rd>, <rn>, #<const>': (0, 1), 'uxtah<c> <rd>, <rn>, <rm>': (1, 1), 'sbc<c> <rd>, <rn>, <rm>, <shift>': (1, 1), 'sxtab<c> <rd>, <rn>, <rm>, <rotation>': (1, 1), 'sub<c> <rd>, <rn>, #<const>': (0, 1), 'usax<c> <rd>, <rn>, <rm>': (1, 1), 'usub16<c> <rd>, <rn>, <rm>': (1, 1), 'mvn<c> <rd>, <rm>, <type> <rs>': (1, 2), 'sub<c> <rd>, <rn>, <rm>, <shift>': (1, 1), 'eor<c> <rd>, <rn>, <rm>, <shift>': (1, 1), 'teq<c> <rn>, <rm>, <type> <rs>': (1, 1), 'bic<c> <rd>, <rn>, <rm>, <shift>': (1, 1), 'shsub8<c> <rd>, <rn>, <rm>': (1, 1), 'uhadd8<c> <rd>, <rn>, <rm>': (1, 1), 'uxth<c> <rd>, <rm>': (0, 1), 'sxtab<c> <rd>, <rn>, <rm>': (1, 1), 'uxtab<c> <rd>, <rn>, <rm>': (1, 1), 'uhsub8<c> <rd>, <rn>, <rm>': (1, 1), 'sub<c> <rd>, sp, <rm>': (1, 1), 'sadd8<c> <rd>, <rn>, <rm>': (1, 1), 'uadd16<c> <rd>, <rn>, <rm>': (1, 1), 'orr<c> <rd>, <rn>, <rm>, <shift>': (1, 1), 'ssat<c> <rd>, #<imm>, <rn>': (1, 1), 'sxtb16<c> <rd>, <rm>': (0, 1), 'rsc<c> <rd>, <rn>, <rm>, <shift>': (1, 1), 'clz<c> <rd>, <rm>': (1, 1), 'rsc<c> <rd>, <rn>, <rm>, <type> <rs>': (1, 1), 'mvn<c> <rd>, <rm>': (1, 1), 'mvn<c> <rd>, #<const>': (1, 1), 'orr<c> <rd>, <rn>, <rm>, <type> <rs>': (1, 1), 'sxtb<c> <rd>, <rm>, <rotation>': (0, 1), 'bic<c> <rd>, <rn>, #<const>': (0, 1), 'tst<c> <rn>, #<const>': (0, 0), 'teq<c> <rn>, #<const>': (0, 0), 'sxtah<c> <rd>, <rn>, <rm>': (1, 1), 'uxtb<c> <rd>, <rm>, <rotation>': (0, 1), 'rsb<c> <rd>, <rn>, <rm>, <type> <rs>': (1, 1), 'tst<c> <rn>, <rm>, <shift>': (1, 1), 'uxtb16<c> <rd>, <rm>, <rotation>': (0, 1), 'and<c> <rd>, <rn>, <rm>': (1, 1), 'sxtab16<c> <rd>, <rn>, <rm>, <rotation>': (1, 1), 'usat<c> <rd>, #<imm>, <rn>, <shift>': (1, 2), 'uasx<c> <rd>, <rn>, <rm>': (1, 1), 'cmn<c> <rn>, <rm>, <type> <rs>': (1, 1), 'rsb<c> <rd>, <rn>, <rm>, <shift>': (1, 1), 'rsc<c> <rd>, <rn>, #<const>': (1, 1), 'sxth<c> <rd>, <rm>, <rotation>': (0, 1), 'uhadd16<c> <rd>, <rn>, <rm>': (1, 1), 'sxtah<c> <rd>, <rn>, <rm>, <rotation>': (1, 1), 'sub<c> <rd>, sp, <rm>, <shift>': (1, 2), 'bxj<c> <rm>': (1, 1), 'uadd8<c> <rd>, <rn>, <rm>': (1, 1), 'blx<c> <rm>': (1, 1), 'uxtab<c> <rd>, <rn>, <rm>, <rotation>': (1, 1), 'shsub16<c> <rd>, <rn>, <rm>': (1, 1), 'sxtb<c> <rd>, <rm>': (0, 1), 'bic<c> <rd>, <rn>, <rm>': (1, 1), 'ssax<c> <rd>, <rn>, <rm>': (1, 1), 'lsl<c> <rd>, <rn>, <rm>': (1, 2), 'sub<c> <rd>, <rn>, <rm>, <type> <rs>': (1, 1), 'teq<c> <rn>, <rm>, <shift>': (1, 1), 'sadd16<c> <rd>, <rn>, <rm>': (1, 1), 'lsr<c> <rd>, <rn>, <rm>': (1, 2), 'sbc<c> <rd>, <rn>, #<const>': (1, 1), 'shsax<c> <rd>, <rn>, <rm>': (1, 1), 'orr<c> <rd>, <rn>, #<const>': (0, 1), 'uxtab16<c> <rd>, <rn>, <rm>': (1, 1), 'eor<c> <rd>, <rn>, <rm>, <type> <rs>': (1, 1), 'uxtb16<c> <rd>, <rm>': (0, 1), 'rsc<c> <rd>, <rn>, <rm>': (1, 1), 'ssub8<c> <rd>, <rn>, <rm>': (1, 1), 'pkhbt<c> <rd>, <rn>, <rm>': (1, 1), 'shadd8<c> <rd>, <rn>, <rm>': (1, 1), 'swp{b}<c> <rt>, <rt2>, <rn>': (1, 1), 'rsb<c> <rd>, <rn>, #<const>': (1, 1), 'uxtb<c> <rd>, <rm>': (0, 1), 'uxtah<c> <rd>, <rn>, <rm>, <rotation>': (1, 1), 'adc<c> <rd>, <rn>, <rm>, <shift>': (1, 1), 'shasx<c> <rd>, <rn>, <rm>': (1, 1), 'and<c> <rd>, <rn>, <rm>, <type> <rs>': (1, 1), 'and<c> <rd>, <rn>, <rm>, <shift>': (1, 1), 'ssat<c> <rd>, #<imm>, <rn>, <shift>': (1, 2), 'usub8<c> <rd>, <rn>, <rm>': (1, 1), 'shadd16<c> <rd>, <rn>, <rm>': (1, 1), 'rev<c> <rd>, <rm>': (1, 2), 'sasx<c> <rd>, <rn>, <rm>': (1, 1), 'udf<c> #<imm>': (1, 1), 'sxth<c> <rd>, <rm>': (0, 1), 'rsb<c> <rd>, <rn>, <rm>': (1, 1), 'tst<c> <rn>, <rm>, <type> <rs>': (1, 1), 'eor<c> <rd>, <rn>, <rm>': (1, 1), 'uxtab16<c> <rd>, <rn>, <rm>, <rotation>': (1, 1), 'sxtb16<c> <rd>, <rm>, <rotation>': (0, 1), 'revsh<c> <rd>, <rm>': (1, 2), 'adc<c> <rd>, <rn>, <rm>': (1, 1), 'bx<c> <rm>': (1, 1), 'uhsax<c> <rd>, <rn>, <rm>': (1, 1), 'bic<c> <rd>, <rn>, <rm>, <type> <rs>': (1, 1), 'lsl<c> <rd>, <rm>, #<imm>': (1, 2), 'lsr<c> <rd>, <rm>, #<imm>': (1, 2), 'asr<c> <rd>, <rm>, #<imm>': (1, 2), 'ror<c> <rd>, <rm>, #<imm>': (1, 2), 'b<c> <label>': (1, 1), 'bl<c> <label>': (1,1), "blx<c> <rm>": (2,2)}

r=cap.CS_AC_READ
w=cap.CS_AC_WRITE
operandtypes_branch = {"beq": [r,r,r], "bne":[r,r,r], "blt":[r,r,r], "bge":[r,r,r],"bltu":[r,r,r],"bgeu":[r,r,r], "beqz":[r,r], "bnez":[r,r], "blez":[r,r],"bgez":[r,r],"bltz":[r,r],"bgtz":[r,r], "bgt":[r,r,r],"ble":[r,r,r],"bgtu":[r,r,r],"bleu":[r,r,r]}
operandtypes_jump = {"j": [r],"jr":[r], "jal":[r, r],"jalr":[w, r, r]}
operandtypes_load = {"lb":[w,r], "lh":[w,r], "lbu":[w,r], "lhu":[w,r], "lw":[w,r]}
operandtypes_store = {"sb":[r,w], "sh":[r,w],"sw":[r,w]}
operandtypes_non_default = {"lui":[w,r],"auipc":[w,r], "li":[w,r],"mv":[w,r],"not":[w,r],"neg":[w,r],"seqz":[w,r], "snez":[w,r],"sltz":[w,r], "sgtz":[w,r]}
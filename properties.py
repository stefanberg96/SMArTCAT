from __future__ import print_function
import insnFormat
import capstone
import capstone.arm_const as capcon

import pipelineModel

class Properties():
    """instruction properties"""
    def __init__(self, insn):
        self.format = insnFormat.format(insn)
        self.insn = insn
        self.resultsBypassed = False
        self.ldr = "ldr" in self.insn.insn_name() 
        self.str = "str" in self.insn.insn_name()
        self.ldm = "ldm" in self.insn.insn_name() 
        self.stm = "stm" in self.insn.insn_name()
        self.pop = "pop" == self.insn.insn_name() 
        self.push = "push" == self.insn.insn_name()
        self.issueTimeSet = False
        self.latencyComputed = False
        self.timeTupleComputed = False
        
    def canDualIssueAsYounger(self):
        return self.format in simpleTiming and simpleTiming[self.format][0] == 0
        #if self.insn.insn_name() in canDualAsYounger:
        #    regsReadCount = 0
        #    for r in self.insn.regs_access()[0]:
        #        if not self.insn.reg_read(r): #validate whether the register wasn't an implicit read
        #            regsReadCount += 1
        #    if regsReadCount == 1:
        #        return True
        #return False
    
    def isEffectiveBranch(self):
        return 11 in self.insn.regs_write or 11 in self.insn.regs_access()[1]      #11 is pipelineModel.REG_MAPPING['pc']
        
    def isTrueBranch(self):
        #these are only true branches if they are conditional, otherwise they are jumps
        return self.insn.insn_name() in ["b", "bl"] and self.insn.cc != 15 and self.insn.cc != 0 \
        or self.insn.insn_name() == "blx" #these can always be true branches because they jump to a register-contained location
        #note: we don't model bx as a true branch. we can't explain how the brain predictor behaves on it
    
    def canDualIssueAsOlder(self):
        return (self.insn.insn_name() in canDualAsYounger or self.format in canDualAsOlder)
        
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
            elif self.format in type1Bailout:
                result = ((1,1), (2,1))
            elif self.format in type2Bailout:
                result = ((1,1), (3,2))
            elif self.format in type3Bailout:
                result = type3Bailout[self.format]
            elif self.str or self.stm or self.push:
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
                elif (self.ldm or self.stm):
                    result = len(self.insn.operands)/2
                    #starting memory location can give a 1 cycle timing difference due to word boundaries. This depends on a combination of the type of load/store multiple, and the starting address. For now we consider this as noise, but it can be modelled more exactly.
                elif (self.pop or self.push):
                    result = (len(self.insn.operands)+1)/2
                else:
                    print ("unmodelled issue time for memory operation %s" % insn.mnemonic)
            elif self.format in simpleTiming:
                time = simpleTiming[self.format][0]
                if time == 0:
                    time == 1
                result = time
            elif self.format in type1Bailout or self.format in type2Bailout:
                result = 1
            elif self.format in type3Bailout:
                result = type3Bailout[self.format][0][0]
            #else: self.issueTime already starts as null
            #    result = None
            self.issueTiming = result
            self.issueTimeSet = True
        return self.issueTiming
        
    def DEPRECATEDlatency(self):
        """
            DEPRECATED
            returns latency for standard instructions
        """
        if self.format in simpleTiming:
            return simpleTiming[self.format][1]
        elif self.format in type1Bailout:
            return 2
        elif self.format in type2Bailout:
            return 3
        elif self.format in type3Bailout:
            return type3Bailout[self.format][1][0]
        else:
            return None
        
    def hasSpecialLatencyNeeds(self):
        """
            returns whether this instruction has special latency requirements.
        """
        return self.ldr or self.ldm or self.pop
        
    def isMemInsn(self):
        """
            returns whether this is a memory instruction (load or store)
        """
        return self.ldr or self.str or self.ldm or self.stm or self.pop or self.push
        
    def specialLatency(self):
        """
            returns a dictionary of registers and their latencies(t/f)
        """
        if not self.latencyComputed:
            latencies = {}
            if self.ldr:
                latencies[self.insn.operands[0].reg] = (self.issueTime()+2, self.issueTime()+1)
                
                if self.insn.writeback:
                    latencies[self.insn.operands[1].mem.base] = (self.issueTime()+1, self.issueTime()+1)
            
            if self.ldm or self.pop:
                #latency partially depends on starting position and inc/decrement type, because of word boundaries. This causes a maximum of 1 cycle differenc, which we consider as noise for now. this is similar to the ldm/stm issue time, and may be modelled more exactly.
                if self.pop:
                    start = 0
                else:
                    start = 1
                for k,o in enumerate(self.insn.operands[start:]):
                    latencies[o.reg] = (max(self.issueTime(),(k+6)/2), max(self.issueTime(),(k+5)/2))
                    
                if self.insn.writeback:
                    latencies[self.insn.operands[0].reg] = (self.issueTime()+1, self.issueTime()+1)
                if self.pop:
                    latencies[pipelineModel.REG_MAPPING['sp']] = (self.issueTime()+1, self.issueTime()+1)
            self.latency = latencies
            self.latencyComputed = True;        
        return self.latency
        
    def ccBailoutTime(self):
        """returns issue and latency time if cc false"""
        if self.format in type1Bailout:
            return (1,1) #since issuing time doesn't change for these instructions we should make sure we don't create unnecessary constraints
        elif self.format in type2Bailout:
            return (1,2) #since issuing time doesn't change for these instructions we should make sure we don't create unnecessary constraints
        elif self.format in type3Bailout:
            return (type3Bailout[self.format][0][1], type3Bailout[self.format][1][1])
        else:
            return None
        
    #def earlyShiftOperands(self):
        #DEPRECATED
        #return which operands are required a cycle early due to shifting
        #might not actually need to model these anymore as I already did it for the timeplugin
    #    return []
        
    def accumulatorReg(self):
        """
            returns the accumulator reg, or None if it has none
            Also returns None if the reg is used as another operand tot a non-accumulator reg.
        """
        #Ra is always an accumulator register and RdLo is too if it is read from (RdLo is read from except with smull and umull instructions, but it is never modelled as a read in capstone, so use workaround)
        if self.format == None:
            return None
        elif "<rdlo>" in self.format and not (self.insn.insn_name() == "umull" or self.insn.insn_name() == "smull"): #self.insn.operands[0].reg in self.insn.regs_access()[0]:
            accumulator = self.insn.operands[0].reg #RdLo is the first operand
            for o in self.insn.operands[1:]:
                if o.reg == accumulator:
                    accumulator = None
            return accumulator
        elif "<ra>" in self.format:
            accumulator = self.insn.operands[len(self.insn.operands)-1].reg #Ra is the last operand
            for o in self.insn.operands[:-1]:
                if o.reg == accumulator:
                    accumulator = None
            return accumulator
        else:
            return None
        
    def isRdHi(self, reg):
        return "<rdhi>" in self.format and reg == self.insn.operands[1].reg #RdHi is always operand 1
        
        
    def canForwardToAccumulator(self): 
        """
            This works given that we only request it for instructions followed by an accumulator instruction.
            TODO low priority: Not sure how instructions with multiple destination addresses cope with this (might only 1 of them be forwarded?)
            TEST says: RdLo has true bypass, RdHi has "half bypass" just like simple arithmetic
            So it probably works
        """
        return not self.isMemInsn()
        
    def canReceiveSemiBypass(self):
        """
            These instructions have "semi" bypasses (if they are not dual-issued of course) which means they can remove 1 cycle from result latency they depend on.
        """
        return self.insn.insn_name() in hasSimpleBypassList
        
    def altRegTimings(self):
        """
            Combines earlyRegs() and lateRegs(), removing lateRegs that also appear as early regs
            returns a list of tuples (register, cycleDifference)
                where cycleDifference is a positive number of cycles for late regs and negative for early regs
        """
        early = self.earlyReg()
        late = self.lateReg()
        combination = []
        for e in early:
            combination.append((e,-1))
        for l in late:
            if l[0] not in early:
                combination.append(l)
        return combination
    
        
    def earlyReg(self):
        """
            returns a list containing early regs, all known early regs are required 1 cycle early
        """
        earlyRegs = set([])
        
        if self.ldm or self.stm:    #Load/store multiple
            earlyRegs.add(self.insn.operands[0].reg)
        if self.pop or self.push:   #pop/push are synonyms of load/store multiple
            earlyRegs.add(pipelineModel.REG_MAPPING['sp'])
        for o in self.insn.operands:    #shift operands
            if o.type == capcon.ARM_OP_REG and o.shift.type != 0:
                earlyRegs.add(o.reg) #the shifted register
                if o.shift.type >= capcon.ARM_SFT_ASR_REG:
                    earlyRegs.add(o.shift.value) #the shift-amount register
            if (self.ldr or self.str) and o.type == capcon.ARM_OP_MEM and not o.subtracted and (o.shift.type == capcon.ARM_SFT_LSL or o.shift.type == 0): # if no subtracted reg offset and no non-left-shift
                earlyRegs.add(o.mem.base)
                if o.mem.index != 0:
                    earlyRegs.add(o.mem.index)
        #all known early regs are required 1 cycle early:
        return earlyRegs
        
    def lateReg(self):
        """
            returns a list containing tuples: (lateRegAddress, #numberOfCyclesLate), one entry for each late reg
            doesn't return the register if it is also used as a non-late  operand
        """
        
        lateReg = []
        posReg = [] #ordered list of late reg operand positions for validation later in function
        #late registers which are also accumulators probably shouldn't be modelled as late regs because we don't want to give them a double timing bonus, so we don't do this.
        if self.insn.insn_name() in ["qdadd", "qdsub", "pkhbt", "umaal"]:
            late = self.insn.operands[1].reg #all these operations have the late reg at position 1
            lateReg = [(late, 1)]
            posReg.append(1)
        elif self.str:
            lateReg = [(self.insn.operands[0].reg, 2)]
            posReg.append(0)
            if self.insn.operands[1].subtracted or (self.insn.operands[1].shift.type != 0 and self.insn.operands[1].shift.type != capcon.ARM_SFT_LSL):
                #if using a negative reg offset or a nonleftshift, base reg also becomes a late reg
                lateReg.append((self.insn.operands[1].mem.base,1))
                posReg.append(1)
                lateReg.append((self.insn.operands[1].mem.index,1))
                posReg.append(2)
        elif self.stm or self.push:
            if self.push:
                start = 0
            else:
                start = 1
            for k,o in enumerate(self.insn.operands[start:]):
                lateReg.append((o.reg,2))
                posReg.append(k+1)
        elif self.ldr and (self.insn.operands[1].subtracted or (self.insn.operands[1].shift.type != 0 and self.insn.operands[1].shift.type != capcon.ARM_SFT_LSL)):
            lateReg.append((self.insn.operands[1].mem.base,1))
            posReg.append(1)
            lateReg.append((self.insn.operands[1].mem.index,1))
            posReg.append(2)
        if self.insn.insn_name() == "swp":
            lateReg.append((self.insn.operands[0].reg, 2))
            posReg.append(0)
            lateReg.append((self.insn.operands[1].reg, 2))
            posReg.append(1)
            lateReg.append((self.insn.operands[2].reg, 2))
            posReg.append(2)
            
            
        #validate whether the registers aren't used other nonlate operands as well (if so, it obviously can't be accessed late)
        #create list of all operand registers:
        allOperandRegs = []
        for o in self.insn.operands:
            if o.type == capcon.ARM_OP_REG and o.access == capstone.CS_AC_READ:  #other operands are only relevant if they are read from
                #NOTE: o.access for STR instructions with writeback is actually NOT capstone.CS_AC_READ, but WRITE instead.
                #however, as these operands always are always 2 cycles late we don't have to worry about them.
                allOperandRegs.append(o.reg)
                if o.shift.type >= capcon.ARM_SFT_ASR_REG:
                    allOperandRegs.append(o.shift.value)
            if o.type == capcon.ARM_OP_MEM:
                allOperandRegs.append(o.mem.base)
                if o.mem.index != 0:
                    allOperandRegs.append(o.mem.index)
        #test late regs for usage as non-late regs:
        for k,o in enumerate(allOperandRegs):
            for i,l in enumerate(lateReg):
                if l != None and o == l[0] and k not in posReg:
                    lateReg[i] = None #mark which operands to be removed from list (can't yet do so here because of iteration)
                    #print(posReg)
                    #print("removing reg %s from list" % (l,))
                    if (l[1]) in posReg:
                        posReg.remove(l[1])
        #test whether regs are used more than once as late regs:
        count = {}
        for k,r in enumerate(lateReg):
            if r != None: 
                if r[0] not in count:
                    count[r[0]] = (r[1],k)
                elif r[1] >= count[r[0]][0]:
                    lateReg[k] = None
                else:
                    lateReg[count[r[0]][1]] = None
                    count[r[0]] = (r[1],k)
        #remove cleaned regs from lateRegs list
        for r in lateReg:
            if r == None:
                lateReg.remove(r)
                    
        return lateReg
        
canDualAsYounger = ["mov", "add", "and", "mvn", "orr", "eor", "sub", "cmp", "cmn", "tst", "teq", "sxtb", "uxtb", "sxth", "uxth", "bic"]
canDualAsOlder = ['rev16<c> <rd>, <rm>', 'uhsub16<c> <rd>, <rn>, <rm>', 'orr<c> <rd>, <rn>, <rm>', 'rrx<c> <rd>, <rm>', 'uadd16<c> <rd>, <rn>, <rm>', 'qdsub<c> <rd>, <rm>, <rn>', 'qasx<c> <rd>, <rn>, <rm>', 'qsub8<c> <rd>, <rn>, <rm>', 'sel<c> <rd>, <rn>, <rm>', 'qsub<c> <rd>, <rm>, <rn>', 'ror<c> <rd>, <rn>, <rm>', 'qdadd<c> <rd>, <rm>, <rn>', 'qsub16<c> <rd>, <rn>, <rm>', 'ssub16<c> <rd>, <rn>, <rm>', 'sbc<c> <rd>, <rn>, <rm>, <type> <rs>', 'sbc<c> <rd>, <rn>, <rm>', 'sxtab16<c> <rd>, <rn>, <rm>', 'adc<c> <rd>, <rn>, #<const>', 'usat16<c> <rd>, #<imm>, <rn>', 'uhasx<c> <rd>, <rn>, <rm>', 'usat<c> <rd>, #<imm>, <rn>', 'uxtah<c> <rd>, <rn>, <rm>, <rotation>', 'adc<c> <rd>, <rn>, <rm>, <type> <rs>', 'add<c> <rd>, sp, <rm>', 'sub<c> <rd>, <rn>, <rm>, <type> <rs>', 'qsax<c> <rd>, <rn>, <rm>', 'mvn<c> <rd>, <rm>, <shift>', 'uxtah<c> <rd>, <rn>, <rm>', 'lsr<c> <rd>, <rm>, #<imm>', 'sbc<c> <rd>, <rn>, <rm>, <shift>', 'sadd16<c> <rd>, <rn>, <rm>', 'usax<c> <rd>, <rn>, <rm>', 'asr<c> <rd>, <rm>, #<imm>', 'usub16<c> <rd>, <rn>, <rm>', 'mvn<c> <rd>, <rm>, <type> <rs>', 'sub<c> <rd>, <rn>, <rm>, <shift>', 'eor<c> <rd>, <rn>, <rm>, <shift>', 'bic<c> <rd>, <rn>, <rm>, <shift>', 'uqadd8<c> <rd>, <rn>, <rm>', 'shsub8<c> <rd>, <rn>, <rm>', 'uhadd8<c> <rd>, <rn>, <rm>', 'sxtab<c> <rd>, <rn>, <rm>', 'uxtab<c> <rd>, <rn>, <rm>', 'ssat16<c> <rd>, #<imm>, <rn>', 'sub<c> <rd>, sp, <rm>', 'lsl<c> <rd>, <rm>, #<imm>', 'uhsub8<c> <rd>, <rn>, <rm>', 'sadd8<c> <rd>, <rn>, <rm>', 'orr<c> <rd>, <rn>, <rm>, <shift>', 'ssat<c> <rd>, #<imm>, <rn>', 'rsc<c> <rd>, <rn>, <rm>, <shift>', 'clz<c> <rd>, <rm>', 'rsc<c> <rd>, <rn>, <rm>, <type> <rs>', 'mvn<c> <rd>, <rm>', 'orr<c> <rd>, <rn>, <rm>, <type> <rs>', 'add<c> <rd>, <rn>, <rm>', 'pkhbt<c> <rd>, <rn>, <rm>, lsl #<imm>', 'sxtah<c> <rd>, <rn>, <rm>', 'rsb<c> <rd>, <rn>, <rm>, <type> <rs>', 'qadd8<c> <rd>, <rn>, <rm>', 'and<c> <rd>, <rn>, <rm>', 'sxtab16<c> <rd>, <rn>, <rm>, <rotation>', 'usat<c> <rd>, #<imm>, <rn>, <shift>', 'uasx<c> <rd>, <rn>, <rm>', 'eor<c> <rd>, <rn>, <rm>', 'rsb<c> <rd>, <rn>, <rm>, <shift>', 'rsc<c> <rd>, <rn>, #<const>', 'uhadd16<c> <rd>, <rn>, <rm>', 'sub<c> <rd>, sp, <rm>, <shift>', 'qadd16<c> <rd>, <rn>, <rm>', 'add<c> <rd>, sp, <rm>, <shift>', 'add<c> <rd>, <rn>, <rm>, <type> <rs>', 'uxtab<c> <rd>, <rn>, <rm>, <rotation>', 'shsub16<c> <rd>, <rn>, <rm>', 'uqadd16<c> <rd>, <rn>, <rm>', 'bic<c> <rd>, <rn>, <rm>', 'ssax<c> <rd>, <rn>, <rm>', 'lsl<c> <rd>, <rn>, <rm>', 'uhsax<c> <rd>, <rn>, <rm>', 'add<c> <rd>, <rn>, <rm>, <shift>', 'qadd<c> <rd>, <rm>, <rn>', 'sub<c> <rd>, <rn>, <rm>', 'asr<c> <rd>, <rn>, <rm>', 'sxtab<c> <rd>, <rn>, <rm>, <rotation>', 'lsr<c> <rd>, <rn>, <rm>', 'sbc<c> <rd>, <rn>, #<const>', 'sxtah<c> <rd>, <rn>, <rm>, <rotation>', 'shsax<c> <rd>, <rn>, <rm>', 'uqsax<c> <rd>, <rn>, <rm>', 'uxtab16<c> <rd>, <rn>, <rm>', 'eor<c> <rd>, <rn>, <rm>, <type> <rs>', 'rsc<c> <rd>, <rn>, <rm>', 'ssub8<c> <rd>, <rn>, <rm>', 'ror<c> <rd>, <rm>, #<imm>', 'uqsub16<c> <rd>, <rn>, <rm>', 'pkhbt<c> <rd>, <rn>, <rm>', 'shadd8<c> <rd>, <rn>, <rm>', 'shadd16<c> <rd>, <rn>, <rm>', 'uqasx<c> <rd>, <rn>, <rm>', 'rsb<c> <rd>, <rn>, #<const>', 'adc<c> <rd>, <rn>, <rm>, <shift>', 'shasx<c> <rd>, <rn>, <rm>', 'and<c> <rd>, <rn>, <rm>, <type> <rs>', 'and<c> <rd>, <rn>, <rm>, <shift>', 'ssat<c> <rd>, #<imm>, <rn>, <shift>', 'usub8<c> <rd>, <rn>, <rm>', 'rev<c> <rd>, <rm>', 'sasx<c> <rd>, <rn>, <rm>', 'uadd8<c> <rd>, <rn>, <rm>', 'rsb<c> <rd>, <rn>, <rm>', 'uxtab16<c> <rd>, <rn>, <rm>, <rotation>', 'revsh<c> <rd>, <rm>', 'adc<c> <rd>, <rn>, <rm>', 'uqsub8<c> <rd>, <rn>, <rm>', 'bic<c> <rd>, <rn>, <rm>, <type> <rs>']

type1Bailout = ['qadd<c> <rd>, <rm>, <rn>', 'qadd16<c> <rd>, <rn>, <rm>', 'qadd8<c> <rd>, <rn>, <rm>', 'qasx<c> <rd>, <rn>, <rm>', 'qsax<c> <rd>, <rn>, <rm>', 'qsub<c> <rd>, <rm>, <rn>', 'qsub16<c> <rd>, <rn>, <rm>', 'qsub8<c> <rd>, <rn>, <rm>', 'smull<c> <rdlo>, <rdhi>, <rn>, <rm>', 'umull<c> <rdlo>, <rdhi>, <rn>, <rm>', 'uqadd16<c> <rd>, <rn>, <rm>', 'uqadd8<c> <rd>, <rn>, <rm>', 'uqasx<c> <rd>, <rn>, <rm>', 'uqsax<c> <rd>, <rn>, <rm>', 'uqsub16<c> <rd>, <rn>, <rm>', 'uqsub8<c> <rd>, <rn>, <rm>'] #type1 issue(t/f) = (1,1) latency(t/f) = (2,1)
type2Bailout = ['mla<c> <rd>, <rn>, <rm>, <ra>', 'mul<c> <rd>, <rn>, <rm>', 'qdadd<c> <rd>, <rm>, <rn>', 'qdsub<c> <rd>, <rm>, <rn>', 'smla<x><y><c> <rd>, <rn>, <rm>, <ra>', 'smlad{x}<c> <rd>, <rn>, <rm>, <ra>', 'smlad{x}<c> <rd>, <rn>, <rm>, <ra>', 'smlal<c> <rdlo>, <rdhi>, <rn>, <rm>', 'smlal<x><y><c> <rdlo>, <rdhi>, <rn>, <rm>', 'smlald{x}<c> <rdlo>, <rdhi>, <rn>, <rm>', 'smlald{x}<c> <rdlo>, <rdhi>, <rn>, <rm>', 'smlaw<y><c> <rd>, <rn>, <rm>, <ra>', 'smlsd{x}<c> <rd>, <rn>, <rm>, <ra>', 'smlsd{x}<c> <rd>, <rn>, <rm>, <ra>', 'smlsld{x}<c> <rdlo>, <rdhi>, <rn>, <rm>', 'smlsld{x}<c> <rdlo>, <rdhi>, <rn>, <rm>', 'smmla{r}<c> <rd>, <rn>, <rm>, <ra>', 'smmla{r}<c> <rd>, <rn>, <rm>, <ra>', 'smmls{r}<c> <rd>, <rn>, <rm>, <ra>', 'smmls{r}<c> <rd>, <rn>, <rm>, <ra>', 'smmul{r}<c> <rd>, <rn>, <rm>', 'smmul{r}<c> <rd>, <rn>, <rm>', 'smuad{x}<c> <rd>, <rn>, <rm>', 'smuad{x}<c> <rd>, <rn>, <rm>', 'smul<x><y><c> <rd>, <rn>, <rm>', 'smulw<y><c> <rd>, <rn>, <rm>', 'smusd{x}<c> <rd>, <rn>, <rm>', 'smusd{x}<c> <rd>, <rn>, <rm>', 'umlal<c> <rdlo>, <rdhi>, <rn>, <rm>', 'usad8<c> <rd>, <rn>, <rm>', 'usada8<c> <rd>, <rn>, <rm>, <ra>'] # type2 issue(t/f) = (1,1) latency(t/f) = (3,2)
type3Bailout = {'push<c> <registers>' : ((3, 2), (3, 2)), "bx<c> <rm>": ((10,2), (10,2)), 'umaal<c> <rdlo>, <rdhi>, <rn>, <rm>' : ((2, 2), (3, 2)), "swp{b}<c> <rt>, <rt2>, [<rn>]" : ((15, 1), (15, 1))} #(issue(t/f), latency(t/f))

hasSimpleBypassList = ["mov", "add", "and", "sub", "cmp", "adc", "eor", "rsb", "sbc", "rsc", "orr", "bic", "mvn", "clz", "uxtb", "sxtb", "uxth", "sxth", "usub8", "ssub8", "usub16", "ssub16", "uadd8", "sadd8", "uadd16", "sadd16", "uhadd8", "shadd8", "uhadd16", "shadd16", "uhsub8", "shsub8", "uhsub16", "shsub16", "qsax", "usax", "ssax", "uhsax", "shsax", "uqsax", "qasx", "uhasx", "uasx", "uqasx", "shasx", "sasx", "uqadd8", "qadd8", "uqadd16", "qadd16", "qadd", "uqsub8", "qsub8", "uqsub16", "qsub16", "qsub", "rsb", "sel", "usat", "usat16", "ssat", "ssat16", "cmn", "tst", "teq"]
 
        
#issue / latency
simpleTiming = {'mov<c> <rd>, #<const>': (0, 1), 'mov<c> <rd>, <rm>': (0, 1), 'cmp<c> <rn>, #<const>': (0, 0), 'cmp<c> <rn>, <rm>': (1, 1), 'cmp<c> <rn>, <rm>, <type> <rs>': (1, 1), 'cmp<c> <rn>, <rm>, <shift>': (1, 1), 'add<c> <rd>, sp, <rm>, <shift>': (1, 2), 'add<c> <rd>, sp, <rm>': (1, 1), 'add<c> <rd>, <rn>, <rm>, <type> <rs>': (1, 1), 'add<c> <rd>, <rn>, #<const>': (0, 1), 'add<c> <rd>, <rn>, <rm>, <shift>': (1, 1), 'add<c> <rd>, <rn>, <rm>': (1, 1), 'pop<c> <registers>': (2, 2), 'rev16<c> <rd>, <rm>': (1, 2), 'uhsub16<c> <rd>, <rn>, <rm>': (1, 1), 'tst<c> <rn>, <rm>': (1, 1), 'eor<c> <rd>, <rn>, #<const>': (0, 1), 'cmn<c> <rn>, #<const>': (0, 0), 'subs <rd>, <rn>, <rm>, <type> <rs>': (1, 1), 'orr<c> <rd>, <rn>, <rm>': (1, 1), 'rrx<c> <rd>, <rm>': (1, 2), 'cmn<c> <rn>, <rm>, <shift>': (1, 1), 'orrs <rd>, <rn>, <rm>, <shift>': (1, 1), 'sel<c> <rd>, <rn>, <rm>': (1, 1), 'orrs <rd>, <rn>, <rm>, <type> <rs>': (1, 1), 'ssat16<c> <rd>, #<imm>, <rn>': (1, 1), 'ror<c> <rd>, <rn>, <rm>': (1, 2), 'sbcs <rd>, <rn>, <rm>, <type> <rs>': (1, 1), 'rrxs <rd>, <rm>': (1, 2), 'teq<c> <rn>, <rm>': (1, 1), 'pkhbt<c> <rd>, <rn>, <rm>, lsl #<imm>': (1, 1), 'ssub16<c> <rd>, <rn>, <rm>': (1, 1), 'sbc<c> <rd>, <rn>, <rm>, <type> <rs>': (1, 1), 'uxth<c> <rd>, <rm>, <rotation>': (0, 1), 'cmn<c> <rn>, <rm>': (1, 1), 'sbc<c> <rd>, <rn>, <rm>': (1, 1), 'sxtab16<c> <rd>, <rn>, <rm>': (1, 1), 'adc<c> <rd>, <rn>, #<const>': (1, 1), 'mlas <rd>, <rn>, <rm>, <ra>': (1, 3), 'usat16<c> <rd>, #<imm>, <rn>': (1, 1), 'uhasx<c> <rd>, <rn>, <rm>': (1, 1), 'usat<c> <rd>, #<imm>, <rn>': (1, 1), 'adc<c> <rd>, <rn>, <rm>, <type> <rs>': (1, 1), 'asr<c> <rd>, <rn>, <rm>': (1, 2), 'sub<c> <rd>, <rn>, <rm>': (1, 1), 'mvn<c> <rd>, <rm>, <shift>': (1, 2), 'and<c> <rd>, <rn>, #<const>': (0, 1), 'uxtah<c> <rd>, <rn>, <rm>': (1, 1), 'sbc<c> <rd>, <rn>, <rm>, <shift>': (1, 1), 'sxtab<c> <rd>, <rn>, <rm>, <rotation>': (1, 1), 'sub<c> <rd>, <rn>, #<const>': (0, 1), 'usax<c> <rd>, <rn>, <rm>': (1, 1), 'usub16<c> <rd>, <rn>, <rm>': (1, 1), 'mvn<c> <rd>, <rm>, <type> <rs>': (1, 2), 'sub<c> <rd>, <rn>, <rm>, <shift>': (1, 1), 'eor<c> <rd>, <rn>, <rm>, <shift>': (1, 1), 'teq<c> <rn>, <rm>, <type> <rs>': (1, 1), 'bic<c> <rd>, <rn>, <rm>, <shift>': (1, 1), 'shsub8<c> <rd>, <rn>, <rm>': (1, 1), 'uhadd8<c> <rd>, <rn>, <rm>': (1, 1), 'uxth<c> <rd>, <rm>': (0, 1), 'sxtab<c> <rd>, <rn>, <rm>': (1, 1), 'uxtab<c> <rd>, <rn>, <rm>': (1, 1), 'uhsub8<c> <rd>, <rn>, <rm>': (1, 1), 'sub<c> <rd>, sp, <rm>': (1, 1), 'sadd8<c> <rd>, <rn>, <rm>': (1, 1), 'uadd16<c> <rd>, <rn>, <rm>': (1, 1), 'orr<c> <rd>, <rn>, <rm>, <shift>': (1, 1), 'ssat<c> <rd>, #<imm>, <rn>': (1, 1), 'sxtb16<c> <rd>, <rm>': (0, 1), 'rsc<c> <rd>, <rn>, <rm>, <shift>': (1, 1), 'clz<c> <rd>, <rm>': (1, 1), 'rsc<c> <rd>, <rn>, <rm>, <type> <rs>': (1, 1), 'mvn<c> <rd>, <rm>': (1, 1), 'mvn<c> <rd>, #<const>': (1, 1), 'orr<c> <rd>, <rn>, <rm>, <type> <rs>': (1, 1), 'sxtb<c> <rd>, <rm>, <rotation>': (0, 1), 'bic<c> <rd>, <rn>, #<const>': (0, 1), 'tst<c> <rn>, #<const>': (0, 0), 'teq<c> <rn>, #<const>': (0, 0), 'sxtah<c> <rd>, <rn>, <rm>': (1, 1), 'uxtb<c> <rd>, <rm>, <rotation>': (0, 1), 'rsb<c> <rd>, <rn>, <rm>, <type> <rs>': (1, 1), 'tst<c> <rn>, <rm>, <shift>': (1, 1), 'uxtb16<c> <rd>, <rm>, <rotation>': (0, 1), 'and<c> <rd>, <rn>, <rm>': (1, 1), 'sxtab16<c> <rd>, <rn>, <rm>, <rotation>': (1, 1), 'usat<c> <rd>, #<imm>, <rn>, <shift>': (1, 2), 'uasx<c> <rd>, <rn>, <rm>': (1, 1), 'cmn<c> <rn>, <rm>, <type> <rs>': (1, 1), 'rsb<c> <rd>, <rn>, <rm>, <shift>': (1, 1), 'rsc<c> <rd>, <rn>, #<const>': (1, 1), 'sxth<c> <rd>, <rm>, <rotation>': (0, 1), 'uhadd16<c> <rd>, <rn>, <rm>': (1, 1), 'sxtah<c> <rd>, <rn>, <rm>, <rotation>': (1, 1), 'sub<c> <rd>, sp, <rm>, <shift>': (1, 2), 'bxj<c> <rm>': (1, 1), 'uadd8<c> <rd>, <rn>, <rm>': (1, 1), 'blx<c> <rm>': (1, 1), 'uxtab<c> <rd>, <rn>, <rm>, <rotation>': (1, 1), 'shsub16<c> <rd>, <rn>, <rm>': (1, 1), 'sxtb<c> <rd>, <rm>': (0, 1), 'bic<c> <rd>, <rn>, <rm>': (1, 1), 'ssax<c> <rd>, <rn>, <rm>': (1, 1), 'lsl<c> <rd>, <rn>, <rm>': (1, 2), 'sub<c> <rd>, <rn>, <rm>, <type> <rs>': (1, 1), 'teq<c> <rn>, <rm>, <shift>': (1, 1), 'sadd16<c> <rd>, <rn>, <rm>': (1, 1), 'lsr<c> <rd>, <rn>, <rm>': (1, 2), 'sbc<c> <rd>, <rn>, #<const>': (1, 1), 'shsax<c> <rd>, <rn>, <rm>': (1, 1), 'orr<c> <rd>, <rn>, #<const>': (0, 1), 'uxtab16<c> <rd>, <rn>, <rm>': (1, 1), 'eor<c> <rd>, <rn>, <rm>, <type> <rs>': (1, 1), 'uxtb16<c> <rd>, <rm>': (0, 1), 'rsc<c> <rd>, <rn>, <rm>': (1, 1), 'ssub8<c> <rd>, <rn>, <rm>': (1, 1), 'pkhbt<c> <rd>, <rn>, <rm>': (1, 1), 'shadd8<c> <rd>, <rn>, <rm>': (1, 1), 'swp{b}<c> <rt>, <rt2>, <rn>': (1, 1), 'rsb<c> <rd>, <rn>, #<const>': (1, 1), 'uxtb<c> <rd>, <rm>': (0, 1), 'uxtah<c> <rd>, <rn>, <rm>, <rotation>': (1, 1), 'adc<c> <rd>, <rn>, <rm>, <shift>': (1, 1), 'shasx<c> <rd>, <rn>, <rm>': (1, 1), 'and<c> <rd>, <rn>, <rm>, <type> <rs>': (1, 1), 'and<c> <rd>, <rn>, <rm>, <shift>': (1, 1), 'ssat<c> <rd>, #<imm>, <rn>, <shift>': (1, 2), 'usub8<c> <rd>, <rn>, <rm>': (1, 1), 'shadd16<c> <rd>, <rn>, <rm>': (1, 1), 'rev<c> <rd>, <rm>': (1, 2), 'sasx<c> <rd>, <rn>, <rm>': (1, 1), 'udf<c> #<imm>': (1, 1), 'sxth<c> <rd>, <rm>': (0, 1), 'rsb<c> <rd>, <rn>, <rm>': (1, 1), 'tst<c> <rn>, <rm>, <type> <rs>': (1, 1), 'eor<c> <rd>, <rn>, <rm>': (1, 1), 'uxtab16<c> <rd>, <rn>, <rm>, <rotation>': (1, 1), 'sxtb16<c> <rd>, <rm>, <rotation>': (0, 1), 'revsh<c> <rd>, <rm>': (1, 2), 'adc<c> <rd>, <rn>, <rm>': (1, 1), 'bx<c> <rm>': (1, 1), 'uhsax<c> <rd>, <rn>, <rm>': (1, 1), 'bic<c> <rd>, <rn>, <rm>, <type> <rs>': (1, 1), 'lsl<c> <rd>, <rm>, #<imm>': (1, 2), 'lsr<c> <rd>, <rm>, #<imm>': (1, 2), 'asr<c> <rd>, <rm>, #<imm>': (1, 2), 'ror<c> <rd>, <rm>, #<imm>': (1, 2), 'b<c> <label>': (1, 1), 'bl<c> <label>': (1,1), "blx<c> <rm>": (2,2)}

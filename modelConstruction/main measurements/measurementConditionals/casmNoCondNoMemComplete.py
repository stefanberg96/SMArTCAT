import re

allInstructions = ["ADC <Rd>, <Rn>, #<const>", "ADC <Rd>, <Rn>, <Rm>, <shift>", "ADC <Rd>, <Rn>, <Rm>", "ADC <Rd>, <Rn>, <Rm>, <type> <Rs>", "ADD <Rd>, <Rn>, #<const>", "ADD <Rd>, <Rn>, <Rm>, <shift>", "ADD <Rd>, <Rn>, <Rm>", "ADD <Rd>, <Rn>, <Rm>, <type> <Rs>", "ADD <Rd>, SP, #<const>", "ADD <Rd>, SP, <Rm>, <shift>", "ADD <Rd>, SP, <Rm>", "ADR <Rd>, <label>", "AND <Rd>, <Rn>, #<const>", "AND <Rd>, <Rn>, <Rm>, <shift>", "AND <Rd>, <Rn>, <Rm>", "AND <Rd>, <Rn>, <Rm>, <type> <Rs>", "ASR <Rd>, <Rm>, #<imm>", "ASR <Rd>, <Rn>, <Rm>", "B <label>", "BIC <Rd>, <Rn>, #<const>", "BIC <Rd>, <Rn>, <Rm>, <shift>", "BIC <Rd>, <Rn>, <Rm>", "BIC <Rd>, <Rn>, <Rm>, <type> <Rs>", "BKPT #<imm16>", "BL <label>", "BLX <Rm>", "BX <Rm>", "CLZ <Rd>, <Rm>", "CMN <Rn>, #<const>", "CMN <Rn>, <Rm>, <shift>", "CMN <Rn>, <Rm>", "CMN <Rn>, <Rm>, <type> <Rs>", "CMP <Rn>, #<const>", "CMP <Rn>, <Rm>, <shift>", "CMP <Rn>, <Rm>", "CMP <Rn>, <Rm>, <type> <Rs>", "DBG #<option>", "DMB <option>", "DSB <option>", "EOR <Rd>, <Rn>, #<const>", "EOR <Rd>, <Rn>, <Rm>, <shift>", "EOR <Rd>, <Rn>, <Rm>", "EOR <Rd>, <Rn>, <Rm>, <type> <Rs>", "ISB <option>", "LSL <Rd>, <Rm>, #<imm5>", "LSL <Rd>, <Rn>, <Rm>", "LSR <Rd>, <Rm>, #<imm>", "LSR <Rd>, <Rn>, <Rm>", "MLA <Rd>, <Rn>, <Rm>, <Ra>", "MOV <Rd>, #<const>", "MOV <Rd>, <Rm>", "MRS <Rd>, <spec_reg>", "MSR <spec_reg>, #<const>", "MSR <spec_reg>, <Rn>", "MUL <Rd>, <Rn>, <Rm>", "MVN <Rd>, #<const>", "MVN <Rd>, <Rm>, <shift>", "MVN <Rd>, <Rm>", "MVN <Rd>, <Rm>, <type> <Rs>", "NOP", "ORR <Rd>, <Rn>, #<const>", "ORR <Rd>, <Rn>, <Rm>, <shift>", "ORR <Rd>, <Rn>, <Rm>", "ORR <Rd>, <Rn>, <Rm>, <type> <Rs>", "QADD <Rd>, <Rm>, <Rn>", "QADD16 <Rd>, <Rn>, <Rm>", "QADD8 <Rd>, <Rn>, <Rm>", "QASX <Rd>, <Rn>, <Rm>", "QDADD <Rd>, <Rm>, <Rn>", "QDSUB <Rd>, <Rm>, <Rn>", "QSAX <Rd>, <Rn>, <Rm>", "QSUB <Rd>, <Rm>, <Rn>", "QSUB16 <Rd>, <Rn>, <Rm>", "QSUB8 <Rd>, <Rn>, <Rm>", "RBIT <Rd>, <Rm>", "REV <Rd>, <Rm>", "REV16 <Rd>, <Rm>", "REVSH <Rd>, <Rm>", "ROR <Rd>, <Rm>, #<imm>", "ROR <Rd>, <Rn>, <Rm>", "RRX <Rd>, <Rm>", "RSB <Rd>, <Rn>, #<const>", "RSB <Rd>, <Rn>, <Rm>, <shift>", "RSB <Rd>, <Rn>, <Rm>", "RSB <Rd>, <Rn>, <Rm>, <type> <Rs>", "RSC <Rd>, <Rn>, #<const>", "RSC <Rd>, <Rn>, <Rm>, <shift>", "RSC <Rd>, <Rn>, <Rm>", "RSC <Rd>, <Rn>, <Rm>, <type> <Rs>",  "SADD16 <Rd>, <Rn>, <Rm>", "SADD8 <Rd>, <Rn>, <Rm>", "SASX <Rd>, <Rn>, <Rm>", "SBC <Rd>, <Rn>, #<const>", "SBC <Rd>, <Rn>, <Rm>, <shift>", "SBC <Rd>, <Rn>, <Rm>", "SBC <Rd>, <Rn>, <Rm>, <type> <Rs>", "SEL <Rd>, <Rn>, <Rm>", "SHADD16 <Rd>, <Rn>, <Rm>", "SHADD8 <Rd>, <Rn>, <Rm>", "SHASX <Rd>, <Rn>, <Rm>", "SHSAX <Rd>, <Rn>, <Rm>", "SHSUB16 <Rd>, <Rn>, <Rm>", "SHSUB8 <Rd>, <Rn>, <Rm>", "SMLA<x><y> <Rd>, <Rn>, <Rm>, <Ra>", "SMLAD{X} <Rd>, <Rn>, <Rm>, <Ra>", "SMLAL <RdLo>, <RdHi>, <Rn>, <Rm>", "SMLALD{X} <RdLo>, <RdHi>, <Rn>, <Rm>", "SMLAW<y> <Rd>, <Rn>, <Rm>, <Ra>", "SMLSD{X} <Rd>, <Rn>, <Rm>, <Ra>", "SMLSLD{X} <RdLo>, <RdHi>, <Rn>, <Rm>", "SMMLA{R} <Rd>, <Rn>, <Rm>, <Ra>", "SMMLS{R} <Rd>, <Rn>, <Rm>, <Ra>", "SMMUL{R} <Rd>, <Rn>, <Rm>", "SMUAD{X} <Rd>, <Rn>, <Rm>", "SMUL<x><y> <Rd>, <Rn>, <Rm>", "SMULL <RdLo>, <RdHi>, <Rn>, <Rm>", "SMULW<y> <Rd>, <Rn>, <Rm>", "SMUSD{X} <Rd>, <Rn>, <Rm>", "SSAT <Rd>, #<imm>, <Rn>, <shift>", "SSAT <Rd>, #<imm>, <Rn>", "SSAT16 <Rd>, #<imm>, <Rn>", "SSAX <Rd>, <Rn>, <Rm>", "SSUB16 <Rd>, <Rn>, <Rm>", "SSUB8 <Rd>, <Rn>, <Rm>", "SUB <Rd>, <Rn>, #<const>", "SUB <Rd>, <Rn>, <Rm>, <shift>", "SUB <Rd>, <Rn>, <Rm>", "SUB <Rd>, <Rn>, <Rm>, <type> <Rs>", "SUB <Rd>, SP, #<const>", "SUB <Rd>, SP, <Rm>, <shift>", "SUB <Rd>, SP, <Rm>", "SXTAB <Rd>, <Rn>, <Rm>, <rotation>", "SXTAB <Rd>, <Rn>, <Rm>", "SXTAB16 <Rd>, <Rn>, <Rm>, <rotation>", "SXTAB16 <Rd>, <Rn>, <Rm>", "SXTAH <Rd>, <Rn>, <Rm>, <rotation>", "SXTAH <Rd>, <Rn>, <Rm>", "SXTB <Rd>, <Rm>, <rotation>", "SXTB <Rd>, <Rm>", "SXTB16 <Rd>, <Rm>, <rotation>", "SXTB16 <Rd>, <Rm>", "SXTH <Rd>, <Rm>, <rotation>", "SXTH <Rd>, <Rm>", "TEQ <Rn>, <Rm>, <shift>", "TEQ <Rn>, <Rm>", "TEQ <Rn>, <Rm>, <type> <Rs>", "TST <Rn>, #<const>", "TST <Rn>, <Rm>, <shift>", "TST <Rn>, <Rm>", "TST <Rn>, <Rm>, <type> <Rs>", "UADD16 <Rd>, <Rn>, <Rm>", "UADD8 <Rd>, <Rn>, <Rm>", "UASX <Rd>, <Rn>, <Rm>", "UBFX <Rd>, <Rn>, #<lsb>, #<width>", "UHADD16 <Rd>, <Rn>, <Rm>", "UHADD8 <Rd>, <Rn>, <Rm>", "UHASX <Rd>, <Rn>, <Rm>", "UHSAX <Rd>, <Rn>, <Rm>", "UHSUB16 <Rd>, <Rn>, <Rm>", "UHSUB8 <Rd>, <Rn>, <Rm>", "UMAAL <RdLo>, <RdHi>, <Rn>, <Rm>", "UMLAL <RdLo>, <RdHi>, <Rn>, <Rm>", "UMULL <RdLo>, <RdHi>, <Rn>, <Rm>", "UQADD16 <Rd>, <Rn>, <Rm>", "UQADD8 <Rd>, <Rn>, <Rm>", "UQASX <Rd>, <Rn>, <Rm>", "UQSAX <Rd>, <Rn>, <Rm>", "UQSUB16 <Rd>, <Rn>, <Rm>", "UQSUB8 <Rd>, <Rn>, <Rm>", "USAD8 <Rd>, <Rn>, <Rm>", "USADA8 <Rd>, <Rn>, <Rm>, <Ra>", "USAT <Rd>, #<imm5>, <Rn>, <shift>", "USAT <Rd>, #<imm5>, <Rn>", "USAT16 <Rd>, #<imm4>, <Rn>", "USAX <Rd>, <Rn>, <Rm>", "USUB16 <Rd>, <Rn>, <Rm>", "USUB8 <Rd>, <Rn>, <Rm>", "UXTAB <Rd>, <Rn>, <Rm>, <rotation>", "UXTAB <Rd>, <Rn>, <Rm>", "UXTAB16 <Rd>, <Rn>, <Rm>, <rotation>", "UXTAB16 <Rd>, <Rn>, <Rm>", "UXTAH <Rd>, <Rn>, <Rm>, <rotation>", "UXTAH <Rd>, <Rn>, <Rm>", "UXTB <Rd>, <Rm>, <rotation>", "UXTB <Rd>, <Rm>", "UXTB16 <Rd>, <Rm>, <rotation>", "UXTB16 <Rd>, <Rm>", "UXTH <Rd>, <Rm>, <rotation>", "UXTH <Rd>, <Rm>", "UMLAL <RdLo>, <RdHi>, <Rn>, <Rm>", "UMULL <RdLo>, <RdHi>, <Rn>, <Rm>"]

conditions = ["", "eq"]
types = ["LSL"]
shifts = ["LSL #3", "LSR #3", "ASR #3", "ROR #3", "RRX"]

registers = ["<Rd>","<RdLo>","<RdHi>","<Rt>","<Rt2>","<Rn>","<Rm>","<Rs>","<Ra>"]

class Formatted:
    """
    returns an iterator over all different instructions we want to generate from this format
    """
    def __init__(self, format):
        self.format = format
        self.optionCount = format.count("{")
        self.maxOptionalParamsStep = 2**self.optionCount
    
    def __iter__(self):
        self.conditionStep = 0
        self.setFlagsStep = 0
        self.typeStep = 0
        self.firstStep = False
        self.plusMinStep = 0
        self.constStep = 0
        self.shiftStep = 0
        self.immStep = 0
        self.optionalParamsStep = 0
        
        return self
        
    def next(self):
        self._bailOnHardInstructions()
        self.regCount = 1
        format = self.format
        cc = self._formatCc(format)
        format = cc[0]
        #format = self._formatS(format)
        format = self._formatRegs(format)
        format = self._formatType(format)
        format = self._formatLSB(format)
        format = self._formatWidth(format)
        format = self._formatRotation(format)
        format = self._formatConst(format)
        format = self._formatShift(format)
        format = self._formatImm(format)
        format = self._formatOptionalParams(format)
        format = self._formatXY(format)
        format = self._formatQ(format)
        format = self._formatRegList(format)
        format = self._formatPlusMin(format)
        
        self._step()
        
        c = cc[1] if self.format.find('<c>') != -1 else None
        return (format, c)
    
    def _formatCc(self, format):
        #format all condition codes
        format = format.replace('<c>',conditions[self.conditionStep])
        return (format, conditions[self.conditionStep])
        
    def _formatS(self, format):
        #format all condition codes
        if self.setFlagsStep == 0:
            format = format.replace('{S}',"S")
        else:
            format = format.replace('{S}',"")
        return format
    
    def _formatRegs(self, format):
        #format all registers
        for reg in registers:
            if format.find(reg) != -1:
                format = format.replace(reg,'r%d'%self.regCount)
                self.regCount += 1
        return format
        
    def _formatType(self, format):
        format = format.replace("<type>", types[self.typeStep])
        return format
        
    def _formatLSB(self, format):
        format = format.replace("<lsb>", "3");
        return format
        
    def _formatWidth(self, format):
        format = format.replace("<width>", "8");
        return format
        
    def _formatXY(self, format):    #TODO: may want to iterate over options
        format = format.replace("<x>", "B");
        format = format.replace("<y>", "T");
        return format
        
    def _formatQ(self, format):    #TODO: may want to iterate over options
        format = format.replace("<q>", ".w");
        return format

    def _formatRotation(self, format):
        format = format.replace("<rotation>", "ROR #8");
        return format
        
    def _formatPlusMin(self, format):
        plusMin = "+" if self.plusMinStep == 0 else "-"
        format = format.replace("+/-", plusMin);
        return format
        
    def _formatConst(self, format):
        const = "77" if self.constStep == 0 else "0" #high entropy number
        format = format.replace("<const>", const);
        return format
        
    def _formatShift(self, format):
        format = format.replace("<shift>", shifts[self.shiftStep])
        return format
        
    def _formatImm(self,format):
        imm = "15" if self.immStep == 0 else "0" #high entropy number
        format = re.sub('<imm[0-9]*>', imm, format)
        return format
        
    def _formatRegList(self,format):
        format = format.replace("<registers>", "{r%d,r%d,r%d}" % (self.regCount, self.regCount+1, self.regCount+2))
        self.regCount += 3
        return format
        
    def _formatOptionalParams(self, format):
        def dropFirstOption(format):
            format = re.sub("{[^}]*}","",format,1)
            return format
            
        def keepFirstOption(format):
            format = format.replace("{","",1)
            format = format.replace("}","",1)
            return format
            
        i = self.optionalParamsStep
        count = self.optionCount
        while count > 0:
            if (i % 2) == 0:
                format = dropFirstOption(format)
            else:
                format = keepFirstOption(format)
            i = i >> 1
            count -= 1
        return format
        
    def _step(self):
        if self.firstStep and self.conditionStep == 0 and self.typeStep == 0 and self.plusMinStep == 0 and self.constStep == 0 and self.shiftStep == 0 and self.immStep == 0 and self.optionalParamsStep == 0:
            raise StopIteration
        else:
            self.firstStep = True
            self.conditionStep = ((self.conditionStep+1) % len(conditions))
            if self.format.find('<c>') == -1: self.conditionStep = 0 #override this step if no <c> in instruction
            if self.conditionStep == 0:
                #self.setFlagsStep = (self.setFlagsStep+1) % 2
                #if self.format.find('{S}') == -1: self.setFlagsStep = 0 #override this step if no {S} in instruction
                #if self.setFlagsStep == 0:
                    #self.typeStep = (self.typeStep+1) % len(types)
                    if self.format.find('<type>') == -1: self.typeStep = 0 #override this step if no <type> in instruction
                    if self.typeStep == 0:
                        #self.plusMinStep = (self.plusMinStep+1) % 2
                        if self.format.find('+/-') == -1: self.plusMinStep = 0 #override this step if no +/- in instruction
                        if self.plusMinStep == 0:
                            #self.constStep = (self.constStep+1) % 2
                            if self.format.find('<const>') == -1: self.constStep = 0 #override this step if no <const> in instruction
                            if self.constStep == 0:
                                #self.shiftStep = (self.shiftStep+1) % len(shifts)
                                if self.format.find('<shift>') == -1: self.shiftStep = 0 #override this step if no <shift> in instruction
                                if self.shiftStep == 0:
                                    #self.immStep = (self.immStep+1) % 2
                                    if len(re.findall('<imm[0-9]*>', self.format)) == 0: self.immStep = 0 #override this step if no <imm##> in instruction
                                    if self.immStep == 0:
                                        self.optionalParamsStep = (self.optionalParamsStep+1) % self.maxOptionalParamsStep
                                        if self.format.find('{') == -1: self.optionalParamsStep = 0 #override this step if no {} in instruction instruction
            
        
    def _bailOnHardInstructions(self):
        """
        stop iterating if certain hard to test instructions are encountered
        """
        if self.format.find('spec_reg') != -1 or self.format.find('label') != -1 or self.format.find('endian_specifier') != -1 or self.format.find('option') != -1 :
            raise StopIteration
        
        
def testFunc():
    counter = 0
    for t in allInstructions:
        f = Formatted(t)
        for insn in f:
            print insn[0]
            counter += 1
    print "%d instructions generated" % counter
    
#testFunc()

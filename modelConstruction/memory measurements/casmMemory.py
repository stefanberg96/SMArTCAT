import re

allInstructions = ["LDM<c> <Rn>{!}, <registers>", "LDMDA<c> <Rn>{!}, <registers>", "LDMDB<c> <Rn>{!}, <registers>", "LDMIB<c> <Rn>{!}, <registers>", "LDR<c> <Rt>, [<Rn>, #+/-<imm12>]", "LDR<c> <Rt>, [<Rn>]", "LDR<c> <Rt>, <label>", "LDR<c> <Rt>, [<Rn>,+/-<Rm>, <shift>]{!}", "LDR<c> <Rt>, [<Rn>,+/-<Rm>]{!}", "LDRB<c> <Rt>, [<Rn>, #+/-<imm12>]", "LDRB<c> <Rt>, [<Rn>]", "LDRB<c> <Rt>, <label>", "LDRB<c> <Rt>, [<Rn>,+/-<Rm>, <shift>]{!}", "LDRB<c> <Rt>, [<Rn>,+/-<Rm>]{!}", "LDRBT<c> <Rt>, [<Rn>], #+/-<imm12>", "LDREX<c> <Rt>, [<Rn>]", "LDRH<c> <Rt>, [<Rn>, #+/-<imm8>]", "LDRH<c> <Rt>, [<Rn>]", "LDRH<c> <Rt>, <label>", "LDRH<c> <Rt>, [<Rn>,+/-<Rm>]{!}", "LDRHT<c> <Rt>, [<Rn>] , #+/-<imm8>", "LDRHT<c> <Rt>, [<Rn>] ", "LDRSB<c> <Rt>, [<Rn>, #+/-<imm8>]", "LDRSB<c> <Rt>, [<Rn>]", "LDRSB<c> <Rt>, <label>", "LDRSB<c> <Rt>, [<Rn>,+/-<Rm>]{!}", "LDRSH<c> <Rt>, [<Rn>, #+/-<imm8>]", "LDRSH<c> <Rt>, [<Rn>]", "LDRSH<c> <Rt>, <label>", "LDRSH<c> <Rt>, [<Rn>,+/-<Rm>]{!}", "LDRT<c> <Rt>, [<Rn>] , #+/-<imm12>", "LDRT<c> <Rt>, [<Rn>] ", "POP<c> <registers>", "PUSH<c> <registers>", "STM<c> <Rn>{!}, <registers>", "STMDA<c> <Rn>{!}, <registers>", "STMDB<c> <Rn>{!}, <registers>", "STMIB<c> <Rn>{!}, <registers>", "STR<c> <Rt>, [<Rn>, #+/-<imm12>]", "STR<c> <Rt>, [<Rn>]", "STR<c> <Rt>, [<Rn>,+/-<Rm>, <shift>]{!}", "STR<c> <Rt>, [<Rn>,+/-<Rm>]{!}", "STRB<c> <Rt>, [<Rn>, #+/-<imm12>]", "STRB<c> <Rt>, [<Rn>]", "STRB<c> <Rt>, [<Rn>,+/-<Rm>, <shift>]{!}", "STRB<c> <Rt>, [<Rn>,+/-<Rm>]{!}", "STRBT<c> <Rt>, [<Rn>], #+/-<imm12>", "STREX<c> <Rd>, <Rt>, [<Rn>]", "STRH<c> <Rt>, [<Rn>{, #+/-<imm8>}]", "STRH<c> <Rt>, [<Rn>,+/-<Rm>]{!}", "STRT<c> <Rt>, [<Rn>] , #+/-<imm12>", "STRT<c> <Rt>, [<Rn>] ", "SWP{B}<c> <Rt>, <Rt2>, [<Rn>]"]

conditions = ["", "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le"]
types = ["LSL"]
shifts = ["LSL #1"]

registers = {"<Rd>":"r4","<Rt>":"r2","<Rt2>":"r3","<Rn>":"sp","<Rm>":"r9"}
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
                format = format.replace(reg,registers[reg])
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
        const = "2" if self.constStep == 0 else "0" #high entropy number
        format = format.replace("<const>", const);
        return format
        
    def _formatShift(self, format):
        format = format.replace("<shift>", shifts[self.shiftStep])
        return format
        
    def _formatImm(self,format):
        imm = "2" if self.immStep == 0 else "0" #high entropy number
        format = re.sub('<imm[0-9]*>', imm, format)
        return format
        
    def _formatRegList(self,format):
        format = format.replace("<registers>", "{r2,r3}")
        self.regCount += 2
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
                        self.plusMinStep = (self.plusMinStep+1) % 2
                        if self.format.find('+/-') == -1: self.plusMinStep = 0 #override this step if no +/- in instruction
                        if self.plusMinStep == 0:
                            #self.constStep = (self.constStep+1) % 2
                            if self.format.find('<const>') == -1: self.constStep = 0 #override this step if no <const> in instruction
                            if self.constStep == 0:
                                self.shiftStep = (self.shiftStep+1) % len(shifts)
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

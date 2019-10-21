from __future__ import print_function
testInstructions = ["0x10560:	push	{r2-r7,fp, lr}", "0x10564:	add	fp, sp, #4", "0x10568:	sub	sp, sp, #0x10", "0x1056c:	str	r0, [fp, #-0x10]", "0x10570:	str	r1, [fp, #-0x14]", "0x10574:	ldr	r3, [pc, #0x50]", "0x10578:	ldr	r3, [r3]", "0x1057c:	str	r3, [fp, #-8]", "0x10580:	movs	r3, #0", "0x10584:	str	r0, [fp, #-0xc]", "0x10588:	ldrseq	r3, [fp, #-0x10]", "0x1058c:	ldr	r2, [fp, #-0x14]", "0x10590:	cmp	r2, #0", "0x10594:	muleq	r1, r3, r2"]

import re


mem = '(?:\[[^\[]*\])'
reg = '(?:(?:r(?:[0-9]|1[0-5]))|sl|fp|ip|sp|lr|pc)'
imm = '#(?:-?(?:(?:0x(?:[0-9a-fA-F])+)|(?:[0-9]+)))'
list = '(?:\{[^\{]*\})'
registers = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "sl",  "fp",  "ip",  "sp",  "lr",  "pc"]
conditions = [None,"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al"]
nonflaggedInstructions = ["mls", "mrs", "vabs", "vcls", "vmrs", "vmls", "vqabs", "vrecps", "vrsqrts"]
nonconditionalInstructions = ["movs", "rscs", "sbcs", "adcs", "bics", "smlals", "smulls", "umlals", "umulls", "vcls", "vnmls", "mls", "muls"]

#TODO: change these classes to a thin wrapper around capstone instructions for easier translation to angr/vex-compatible registers

def test():
    for ti in testInstructions:
        i = Instruction(ti)
        print(ti)
        print("address: %s" % i.address())
        print("mnemonic: %s" % i.mnemonic)
        print("core mnemonic: %s" % i.coreMnemonic())
        print("condition: %s" % i.condition())
        print("updateFlags: %s" % i.updateFlags())
        print("operand string: %s" % i.operandsString)
        print("operands: %s" % i.operands())
        print("")
        print("-----------------------------")
        print("")

class Mem():
    """
    TODO: implement offset and shifts
    DEPRECATED
    """
    def __init__(self, string):
        self.string = string
        self.value = None
        
    def registers(self):
        return re.findall('(%s)' % (reg), self.string)

    def __repr__(self):
        return self.__str__()
        
    def __str__(self):
        return self.string
        
class Reg():
    def __init__(self, string):
        self.string = string
        self.value = None
        
    def __repr__(self):
        return self.__str__()
        
    def __str__(self):
        return self.string
    
class Instruction():
    """
    represents an assembly instruction
    TODO: decomposing memory
    TODO: analysing shifts
    """
    def __init__(self, stringRepresentation):
        self.string = stringRepresentation+" "
        self.splitInst = stringRepresentation.split()
        self.mnemonic = self.splitInst[1]
        self.stringNoAddr = stringRepresentation[len(self.splitInst[0])+1:]
        self.operandsString = stringRepresentation[len(self.splitInst[0])+len(self.splitInst[1])+2:]
        self.addressVal = None
        self.memoryComputed = False
        self.immediateVal = None
    
    def shift(self):
        """
        returns the shift type and distance or None if no shift is applied
        TODO: implement
        """
        raise NotImplementedError("support for shifted operands isn't implemented yet")
        return None
    
    def coreMnemonic(self):
        offset = 0
        if self.condition():
            offset -= 2
        if self.updateFlags():
            offset -= 1
        if offset < 0:
            return self.mnemonic[:offset]
        else:
            return self.mnemonic
        
    
    def condition(self):
        """
        returns the conditional identifier string or None if the condition is always ('al')
        """
        if self.mnemonic[-2:] in conditions and self.mnemonic not in nonconditionalInstructions:
            return self.mnemonic[-2:]
        else:
            return None
        
        
    def updateFlags(self):
        """
        returns whether the instruction updates the states flags
        """
        offset = 0 if self.condition() == None else -2
        if offset == 0:
            return (self.mnemonic[-1:] == 's' and not self.mnemonic in nonflaggedInstructions)
        else:
            return (self.mnemonic[-3:-2] == 's' and not self.mnemonic in nonflaggedInstructions)

    def address(self):
        """
        returns the instruction address
        """
        if not self.addressVal:
            self.addressVal = self.splitInst[0][:-1]
        return self.addressVal
        
    def memory(self):
        """
        returns the string contents in between the [] for the memory location used by this instruction, or None if it doesn't use any
        """
        if not self.memoryComputed:
            memoryOccurences = re.findall('\[[^\[]*\]',self.string)
            if len(memoryOccurences) == 0:
                self.memoryLoc = None
            elif len(memoryOccurences) > 2:
                raise NotImplementedError("Encountered multiple memory addresses for instruction: %s" % self.string)
            else:
                self.memoryLoc = memoryOccurences[0]
            self.memoryComputed = True
        return self.memoryLoc
    
    #these seem most functional:
    def operands(self):
        """
        returns all operands of the instruction as a list (of strings?) (TODO)
        """
        results = []
        operandMatches = re.findall('((%s)|(%s)|(%s)|(%s))' % (mem, reg, imm, list), self.operandsString)
        for o in operandMatches:
            if o[1] != '':
                results.append(Mem(self.decomposeMemory(o[1])))
            if o[2] != '':
                results.append(Reg(o[2]))
            if o[3] != '':
                results.append(self.decomposeImmediate(o[3][1:]))
            if o[4] != '':
                results.extend(self.decomposeList(o[4]))
        return results
        
    def decomposeList(self, listString):
        elements = []
        range = '(?:%s-%s)' % (reg, reg)
        superElements = re.findall('((%s)|(%s))' % (range, reg), listString)
        for s in superElements:
            if s[1] != '':
                elements.extend(self.decomposeRange(s[1]))
            else:
                elements.append(Reg(s[0]))
        return elements

    def decomposeRange(self, rangeString):
        bounds = re.findall('(%s)' % (reg), rangeString)
        result = []
        for r in registers[registers.index(bounds[0]):registers.index(bounds[1])+1]:
            result.append(Reg(r))
        return result
        
    def decomposeMemory(self, mem):
        #TODO? does this need actually need to exist?
        return mem
        
    def decomposeImmediate(self, immString):
        """
        returns the immediate value from this instruction or None if it has none
        """
        base = 16 if immString[:2] == "0x" else 10
        return int(immString, base)
        
#test()
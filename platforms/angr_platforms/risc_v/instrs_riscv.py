import abc
from .arch_risc_v import ArchRISCV
from pyvex.lifting.util import Instruction, JumpKind, ParseError, Type
import bitstring
from bitstring import Bits
import logging
l = logging.getLogger(__name__)

REGISTER_TYPE = Type.int_32
BYTE_TYPE = Type.int_8
INDEX_TYPE = Type.int_16


# Lots of things are going to be interpreted as signed immediates. Here's a quickie to load them
def bits_to_signed_int(s):
    return Bits(bin=s).int


class R_Instruction(Instruction):
    '''
    bitformat:
    o = opcode
    d = destination register
    s = source register
    S = source 2 register
    f = func3 
    F = func7
    '''
    opcode = NotImplemented  # binary string of length 6 consisting of the opcode
    func7 = NotImplemented  # binary string of length 7 consisting of the func7 code
    func3 = NotImplemented  # binary string of length 3 consisting of the func3 code

    bit_format = "oooooodddddfffsssssSSSSSFFFFFFF"

    def match_instruction(self, data, bitstream):
        if data['o'] != self.opcode:
            raise ParseError("Invalid opcode, expected %s, got %s" %
                             (self.opcode, data['o']))
        elif data['f'] != self.func3:
            raise ParseError("Invalid func3, expected %s, got %s" %
                             (self.func3, data['f']))
        elif data['F'] != self.func7:
            raise ParseError("Invalid func7, expected %s, got %s" %
                             (self.func7, data['F']))
        return True

    def get_dst_reg(self):
        return int(self.data['d'], 2)

    def get_src1(self):
        return self.get(int(self.data['s'], 2), Type.int_32)

    def get_src2(self):
        return self.get(int(self.data['S'], 2), Type.int_32)

    def fetch_operands(self):
        return self.get_src1(), self.get_src2()

    def commit_result(self, result):
        self.put(result, self.get_dst_reg())


class I_Instruction(Instruction):
    '''
    bitformat:
    o = opcode
    d = destination register
    s = source register
    f = func3 code
    I = first 5 bits of the immediate
    i = last 7 bits of the immediate

    A split was made between i and I since the shift instruction use on the first 5 bits of the
    immediate to determine what the shift amount. The other 7 are used as a func7 value.
    '''
    opcode = NotImplemented  # binary string of length 6 consisting of the opcode
    func3 = NotImplemented  # binary string of length 3 consisting of the func3 code

    bit_format = "oooooodddddfffsssssIIIIIiiiiiii"

    '''In the shift instruction extend this function to also check the last 7 bits of the immediate'''

    def match_instruction(self, data, bitstream):
        if data['o'] != self.opcode:
            raise ParseError("Invalid opcode, expected %s, got %s" %
                             (self.opcode, data['o']))
        elif data['f'] != self.func3:
            raise ParseError("Invalid func3, expected %s, got %s" %
                             (self.func3, data['f']))
        return True

    def get_dst_reg(self):
        return int(self.data['d'], 2)

    def get_src(self):
        return self.get(int(self.data['s'], 2), Type.int_32)

    def get_imm(self):
        return self.constant(int(self.data['I'].append(self.data(['i'])), 2), Type.int_32)

    def get_shift_amount(self):
        return self.constant(int(self.data['I'], 2), Type.int_32)

    def fetch_operands(self):
        return self.get_src(), self.get_imm(), self.get_shift_amount()

    def commit_result(self, result):
        self.put(result, self.get_dst_reg())


class S_Instruction(Instruction):
    '''
    bitformat:
    o = opcode
    i = first 5 bits of the immediate
    f = func3 code
    s = address where to store the value
    S = value to be stored
    I = last 7 bits of the immediate
    '''
    opcode = NotImplemented  # binary string of length 6 consisting of the opcode
    func3 = NotImplemented  # binary string of length 3 consisting of the func3 code

    bit_format = 'ooooooiiiiifffsssssSSSSSIIIIIII'

    def match_instruction(self, data, bitstream):
        if data['o'] != self.opcode:
            raise ParseError("Invalid opcode, expected %s, got %s" %
                             (self.opcode, data['o']))
        elif data['f'] != self.func3:
            raise ParseError("Invalid func3, expected %s, got %s" %
                             (self.func3, data['f']))
        return True

    '''This is the address + offset'''

    def get_addr(self):
        addr = int(self.data['s'], 2)
        offset = int(self.data['i'].append(self.data['I']), 2)
        return self.constant(addr + offset, Type.int_32)

    '''Value is returned as int32 caller must and it to store half words or bytes'''

    def get_val(self):
        return self.get(int(self.data['S'], 2), Type.int32)
    
    def fetch_operands(self):
        return self.get_val(), self.get_addr()

    def commit_result(self, result):
        self.put(result, self.get_addr())

class B_Instruction(Instruction):
    '''
    bitformat:
    o = opcode
    i = first 5 bits of the immediate
    f = func3 code
    s = source register
    S = source 2 register
    I = last 7 bits of the immediate
    '''
    opcode = NotImplemented  # binary string of length 6 consisting of the opcode
    func3 = NotImplemented  # binary string of length 3 consisting of the func3 code

    bit_format = 'ooooooiiiiifffsssssSSSSSIIIIIII'

    def match_instruction(self, data, bitstream):
        if data['o'] != self.opcode:
            raise ParseError("Invalid opcode, expected %s, got %s" %
                             (self.opcode, data['o']))
        elif data['f'] != self.func3:
            raise ParseError("Invalid func3, expected %s, got %s" %
                             (self.func3, data['f']))
        return True

    def get_src1(self):
        return self.get(int(self.data['s'], 2), Type.int_32)

    def get_src2(self):
        return self.get(int(self.data['S'], 2), Type.int_32)

    ''' The offset for B instructions is as follows inst[31]inst[7]inst[30:25]inst[11:8]'''

    def get_offset(self):
        begin = self.data['i'][1:4]
        middle = self.data['I'][0:5]
        x = self.data['i'][5]
        sign = self.data['I'][6]
        offset = begin.append(middle).append(x).append(sign)
        return self.constant(int(offset, 2), Type.int__32)

    def fetch_operands(self):
        return self.get_src1(), self.get_src2()


class U_Instruction(Instruction):
    '''
    bitformat:
    o = opcode
    d = destination register
    i = immediate
    '''

    opcode = NotImplemented  # binary string of length 6 consisting of the opcode

    bit_format = 'oooooodddddiiiiiiiiiiiiiiiiiiii'

    def match_instruction(self, data, bitstream):
        if data['o'] != self.opcode:
            raise ParseError("Invalid opcode, expected %s, got %s" %
                             (self.opcode, data['o']))
        return True

    def get_dst(self):
        return self.get(int(self.data['d'], 2), Type.int_32)

    def get_imm(self):
        return self.constant(int(self.data['i'], 2), Type.int_32)
    
    def fetch_operands(self):
        return self.get_dst(), self.get_imm()


class J_Instruction(Instruction):
    '''
    bitformat:
    o = opcode
    d = destination register
    i = immediate
    '''

    opcode = NotImplemented  # binary string of length 6 consisting of the opcode

    bit_format = 'oooooodddddiiiiiiiiiiiiiiiiiiii'

    def match_instruction(self, data, bitstream):
        if data['o'] != self.opcode:
            raise ParseError("Invalid opcode, expected %s, got %s" %
                             (self.opcode, data['o']))
        return True

    def get_dst(self):
        return self.get(int(self.data['d'], 2), Type.int_32)

    ''''
    Some weird way to parse the immediate according to risc-v isa
    '''

    def get_imm(self):
        return self.constant(int(self.data['i'][12:19].append(self.data[11]).append(self.data[1:10]).append(self.data[20]), 2), Type.int_32)

    def fetch_operands(self):
        return self.get_imm(), self.get_dst()


class Instruction_ADD(R_Instruction):
    func3 = '000'
    func7 = '0000000'
    opcode = '0000011'

    def compute_result(self, src1, src2 ):
        return src1 + src2

class Instruction_SUB(R_Instruction):
    func3 = '000'
    func7 = '0100000'
    opcode = '0000011'
 
    def compute_result(self, src1, src2):
        return src1 - src2
    
class Instruction_XOR(R_Instruction):
    func3 = '100'
    func7 = '0000000'
    opcode = '0000011'
 
    def compute_result(self, src1, src2):
        return src1 ^ src2

class Instruction_OR(R_Instruction):
    func3 = '110'
    func7 = '0000000'
    opcode = '0000011'
 
    def compute_result(self, src1, src2):
        return src1 | src2
    
class Instruction_AND(R_Instruction):
    func3 = '111'
    func7 = '0000000'
    opcode = '0000011'
 
    def compute_result(self, src1, src2):
        return src1 & src2

class Instruction_SLL(R_Instruction):
    func3 = '001'
    func7 = '0000000'
    opcode = '0000011'
 
    def compute_result(self, src1, src2):
        return src1 << src2

class Instruction_SRL(R_Instruction):
    func3 = '010'
    func7 = '0000000'
    opcode = '0000011'
 
    def compute_result(self, src1, src2):
        return src1 >> src2

#Arithmetic shift is not easily mapped, so leaving this as an TODO
class Instruction_SRA(R_Instruction):
    func3 = '011'
    func7 = '0100000'
    opcode = '0000011'
 
    def compute_result(self, src1, src2):
        return src1 >> src2

class Instruction_SLT(R_Instruction):
    func3 = '010'
    func7 = '0000000'
    opcode = '0110011'
 
    def compute_result(self, src1, src2):
        src1.is_signed = True
        src2.is_signed = True
        val = 1 if src1 < src2 else 0
        return self.constant(val, Type.int_32)

class Instruction_SLTU(R_Instruction):
    func3 = '011'
    func7 = '0000000'
    opcode = '0110011'
 
    def compute_result(self, src1, src2):
        src1.is_signed=False
        src1.is_signed=False
        val = 1 if src1 < src2 else 0
        return self.constant(val, Type.int_32)


import abc
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

    def get_optional_func7(self):
        return self.data['i']

    def fetch_operands(self):
        return self.get_src(), self.get_imm()

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
        res =  self.constant(addr + offset, Type.int_32)
        res.is_signed = True
        return res

    '''Value is returned as int32 caller must cast it to store half words or bytes'''

    def get_val(self):
        return self.get(int(self.data['S'], 2), Type.int32)

    def fetch_operands(self):
        return self.get_val()

    def commit_result(self, result):
        self.store(result, self.get_addr())


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
        val = self.constant(int(offset, 2), Type.int__32)
        val.is_signed = True
        return val

    def fetch_operands(self):
        return self.get_src1(), self.get_src2(), self.get_offset()


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
        return int(self.data['d'], 2)

    def get_imm(self):
        return self.constant(int(self.data['i'], 2), Type.int_32)

    def fetch_operands(self):
        return self.get_dst(), self.get_imm()

    def commit_result(self, result):
        self.put(result, self.get_dst())


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
        return int(self.data['d'], 2)

    ''''
    Some weird way to parse the immediate according to risc-v isa
    '''

    def get_imm(self):
        return self.constant(int(self.data['i'][12:19].append(self.data[11]).append(self.data[1:10]).append(self.data[20]), 2), Type.int_32)

    def fetch_operands(self):
        return self.get_imm()

    def commit_result(self, result):
        self.put(result, self.get_dst())


class Instruction_ADD(R_Instruction):
    func3 = '000'
    func7 = '0000000'
    opcode = '0110011'

    def compute_result(self, src1, src2):
        return src1 + src2


class Instruction_SUB(R_Instruction):
    func3 = '000'
    func7 = '0100000'
    opcode = '0110011'

    def compute_result(self, src1, src2):
        return src1 - src2


class Instruction_XOR(R_Instruction):
    func3 = '100'
    func7 = '0000000'
    opcode = '0110011'

    def compute_result(self, src1, src2):
        return src1 ^ src2


class Instruction_OR(R_Instruction):
    func3 = '110'
    func7 = '0000000'
    opcode = '0110011'

    def compute_result(self, src1, src2):
        return src1 | src2


class Instruction_AND(R_Instruction):
    func3 = '111'
    func7 = '0000000'
    opcode = '0110011'

    def compute_result(self, src1, src2):
        return src1 & src2


class Instruction_SLL(R_Instruction):
    func3 = '001'
    func7 = '0000000'
    opcode = '0110011'

    def compute_result(self, src1, src2):
        return src1 << src2


class Instruction_SRL(R_Instruction):
    func3 = '101'
    func7 = '0000000'
    opcode = '0110011'

    def compute_result(self, src1, src2):
        return src1 >> src2

# Arithmetic shift is not easily mapped, so leaving this as an TODO


class Instruction_SRA(R_Instruction):
    func3 = '101'
    func7 = '0100000'
    opcode = '0110011'

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
        src1.is_signed = False
        src1.is_signed = False
        val = 1 if src1 < src2 else 0
        return self.constant(val, Type.int_32)


class Instruction_ADDI(I_Instruction):
    func3 = '000'
    opcode = '0010011'

    def compute_result(self, src1, imm):
       imm.is_signed = True
       return src1 + imm 

class Instruction_XORI(I_Instruction):
    func3='100'
    opcode='0010011'

    def compute_result(self, src1, imm):
        return src1 ^ imm

class Instruction_ORI(I_Instruction):
    func3='110'
    opcode='0010011'
    
    def compute_result(self, src1, imm):
        return src1 | imm

class Instruction_ANDI(I_Instruction):
    func3='111'
    opcode='0010011'

    def compute_result(self, src1, imm):
        return src1 & imm

class Instruction_SLLI(I_Instruction):
    func3='001'
    func7='0000000'
    opcode='0010011'

    def match_instruction(self, data, bitstream ):
        super.match_instruction(self, data, bitstream)
        if(data['i']!= self.func7):
            raise ParseError("The func7 did not match")
        return True

    def compute_result(self, src1, _):
        return src1 << self.get_shift_amount()

class Instruction_SRLI(I_Instruction):
    func3='101'
    func7='0000000'
    opcode='0010011'

    def match_instruction(self, data, bitstream ):
        super.match_instruction(self, data, bitstream)
        if(data['i']!= self.func7):
            raise ParseError("The func7 did not match")
        return True

    def compute_result(self, src1, _):
        return src1 >> self.get_shift_amount()

#Once again issue with arithmetic right shifts, so for the moment still a TODO like SRA
class Instruction_SRAI(I_Instruction):
    func3='101'
    func7='0100000'
    opcode='0010011'

    def match_instruction(self, data, bitstream ):
        super.match_instruction(self, data, bitstream)
        if(data['i']!= self.func7):
            raise ParseError("The func7 did not match")
        return True

    def compute_result(self, src1, _):
        return src1 >> self.get_shift_amount()

class Instruction_SLTI(I_Instruction):
    func3='010'
    opcode='0010011'

    def match_instruction(self, src1, imm):
        src1.is_signed = True
        imm.is_signed = True
        val = 1 if src1 < imm else 0
        return self.constant(val, Type.int_32)
    
class Instruction_SLTIU(I_Instruction):
    func3='011'
    opcode='0010011'

    def match_instruction(self, src1, imm):
        src1.is_signed = False
        imm.is_signed = False
        val = 1 if src1 < imm else 0
        return self.constant(val, Type.int_32)
    
class Instruction_MUL(R_Instruction):
    func3='000'
    func7='0000001'
    opcode='0110011'

    def compute_result(self, src1, src2):
        return (src1*src2) & self.constant(0xFFFF, Type.int_32)

class Instruction_MULH(R_Instruction):
    func3='001'
    func7='0000001'
    opcode='0110011'

    def compute_result(self, src1, src2):
        return (src1*src2)>>self.constant(32,Type.int_8)

class Instruction_MULSU(R_Instruction):
    func3='010'
    func7='0000001'
    opcode='0110011'

    def compute_result(self, src1, src2):
        src1.is_signed = True
        src2.is_signed = False
        return (src1*src2) & self.constant(0xFFFF, Type.int_32)

class Instruction_MULHU(R_Instruction):
    func3='011'
    func7='0000001'
    opcode='0110011'

    def compute_result(self, src1, src2):
        src1.is_signed = False
        src2.is_signed = False
        return (src1*src2)>>self.constant(32,Type.int_8)

class Instruction_DIV(R_Instruction):
    func3='100'
    func7='0000001'
    opcode='0110011'

    def compute_result(self, src1, src2):
        src1.is_signed = True
        src2.is_signed = True
        return src1/src2

class Instruction_DIVU(R_Instruction):
    func3='101'
    func7='0000001'
    opcode='0110011'

    def compute_result(self, src1, src2):
        src1.is_signed = False
        src2.is_signed = False
        return src1/src2

class Instruction_REM(R_Instruction):
    func3='110'
    func7='0000001'
    opcode='0110011'

    def compute_result(self, src1, src2):
        src1.is_signed = True
        src2.is_signed = True
        return src1%src2

class Instruction_REMU(R_Instruction):
    func3='111'
    func7='0000001'
    opcode='0110011'

    def compute_result(self, src1, src2):
        src1.is_signed = False
        src2.is_signed = False
        return src1/src2

class Instruction_LB(I_Instruction):
    func3='000'
    opcode='0000011'

    def compute_result(self, src, imm):
        imm.is_signed = True
        addr = src + imm
        value = self.load(addr, Type.int_8)
        value._is_signed=True
        return value

class Instruction_LH(I_Instruction):
    func3='001'
    opcode='0000011'

    def compute_result(self, src, imm):
        addr = src + imm
        value = self.load(addr, Type.int_16)
        value._is_signed = True
        return value

class Instruction_LW(I_Instruction):
    func3='010'
    opcode='0000011'

    def compute_result(self, src, imm):
        imm.is_signed = True
        addr = src + imm
        value = self.load(addr, Type.int_32)
        value._is_signed=True
        return value

class Instruction_LBU(I_Instruction):
    func3='100'
    opcode = '0000011'

    def compute_result(self, src, imm):
        imm.is_signed = True
        addr = src + imm
        return self.load(addr, Type.int_8)

class Instruction_LHU(I_Instruction):
    func3='101'
    opcode='0000011'

    def compute_result(self, src, imm):
        imm.is_signed = True
        addr= src+imm
        return self.load(addr, Type.int_16)

class Instruction_SB(S_Instruction):
    func3='000'
    opcode= '0100011'

    def compute_result(self, val):
        return val.cast_to(Type.int_8)

class Instruction_SH(S_Instruction):
    func3='001'
    opcode= '0100011'

    def compute_result(self, val):
        return val.cast_to(Type.int_16)

class Instruction_SW(S_Instruction):
    func3='010'
    opcode= '0100011'

    def compute_result(self, val):
        return val

class Instruction_BEQ(B_Instruction):
    func3='000'
    opcode='1100011'

    def compute_result(self, src1, src2, imm):
        addr = self.addr + imm
        self.jump(src1 == src2, addr)

class Instruction_BNE(B_Instruction):
    func3='001'
    opcode = '1100011'

    def compute_result(self, src1, src2, imm):
        addr = self.addr+imm
        self.jump(src1!=src2, addr)

class Instruction_BLT(B_Instruction):
    func3='100'
    opcode='1100011'

    def compute_result(self, src1, src2, imm):
        src1.is_signed = True
        src2.is_signed = True
        addr = self.addr + imm
        self.jump(src1<src2, addr)

class Instruction_BGE(B_Instruction):
    func3='101'
    opcode = '1100011'

    def compute_result(self, src1, src2, imm):
        src1.is_signed = True
        src2.is_signed = True
        addr = self.addr + imm
        self.jump(src1>=src2, addr)

class Instruction_BLTU(B_Instruction):
    func3='110'
    opcode='1100011'

    def compute_result(self, src1, src2, imm):
        src1.is_signed = False
        src2.is_signed = False
        addr = self.addr + imm
        self.jump(src1<src2, addr)

class Instruction_BGEU(B_Instruction):
    func3='111'
    opcode='1100011'

    def compute_result(self, src1, src2, imm):
        src1.is_signed = False
        src2.is_signed = False
        addr = self.addr + imm
        self.jump(src1>= src2, addr)

class Instruction_JALR(I_Instruction):
    func3='000'
    opcode = '1100111'

    def compute_result(self, src, imm):
        imm.is_signed = True
        return_addr = self.addr + self.constant(4, Type.int_32)
        addr = src + imm
        self.jump(None, addr, JumpKind.Call)
        return return_addr

class Instruction_JAL(J_Instruction):
    opcode = '1101111'

    def compute_result(self, imm):
        imm.is_signed = True
        return_addr = self.addr + self.constant(4, Type.int_32)
        addr = self.addr+imm
        self.jump(None, addr)
        return return_addr

class Instruction_LUI(U_Instruction):
    opcode='0110111'

    def compute_result(self, imm):
        return imm << self.constant(12, Type.int_8)

class Instruction_AUIPC(U_Instruction):
    opcode='0010111'

    def compute_result(self, imm):
        return self.addr + (imm << self.constant(12, Type.int_8))

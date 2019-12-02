from archinfo.arch import register_arch, Arch, Register
#copied from arch msp430
class ArchRISCV(Arch):
    def __init__(self, endness="Iend_LE"):
        super(ArchRISCV, self).__init__(endness)
        self.call_pushes_ret = True
        self.branch_delay_slot = False
    sizeof = {'short': 16, 'int': 32, 'long': 32, 'long long': 64}
    function_prologs = {}
    function_epilogs = {}

    bits = 32
    name = "RISCV"
    instruction_endness = "Iend_LE" 
    max_inst_bytes = 4
    instruction_alignment = 4
    persistent_regs = []
    ret_instruction=b"\x37\x00\x08\x00"
    nop_instruction=b"\x13\x00\x00\x00"

    registers = [
       Register(name="x0", size = 4, alias_names=('zero',)),
       Register(name='x1', size = 4, alias_names=('ra',), general_purpose=True),
       Register(name='x2', size = 4, alias_names=('sp',), general_purpose=True, default_value=(Arch.initial_sp, True, 'global')),
       Register(name='x3', size = 4, alias_names=('gp',), general_purpose=True),
       Register(name='x4', size = 4, alias_names=('tp',), general_purpose=True),
       Register(name='x5', size = 4, alias_names=('t0',), general_purpose=True),
       Register(name='x6', size = 4, alias_names=('t1',), general_purpose=True),
       Register(name='x7', size = 4, alias_names=('t2',), general_purpose=True),
       Register(name='x8', size = 4, alias_names=('s0','fp'), general_purpose=True),
       Register(name='x9', size = 4, alias_names=('s1'), general_purpose=True),
       Register(name='x10', size = 4, alias_names=('a0'), general_purpose=True, argument=True),
       Register(name='x11', size = 4, alias_names=('a1'), general_purpose=True, argument=True),
       Register(name='x12', size = 4, alias_names=('a2'), general_purpose=True, argument=True),
       Register(name='x13', size = 4, alias_names=('a3'), general_purpose=True, argument=True),
       Register(name='x14', size = 4, alias_names=('a4'), general_purpose=True, argument=True),
       Register(name='x15', size = 4, alias_names=('a5'), general_purpose=True, argument=True),
       Register(name='x16', size = 4, alias_names=('a6'), general_purpose=True, argument=True),
       Register(name='x17', size = 4, alias_names=('a7'), general_purpose=True, argument=True),
       Register(name='x18', size = 4, alias_names=('s2'), general_purpose=True),
       Register(name='x19', size = 4, alias_names=('s3'), general_purpose=True),
       Register(name='x20', size = 4, alias_names=('s4'), general_purpose=True),
       Register(name='x21', size = 4, alias_names=('s5'), general_purpose=True),
       Register(name='x22', size = 4, alias_names=('s6'), general_purpose=True),
       Register(name='x23', size = 4, alias_names=('s7'), general_purpose=True),
       Register(name='x24', size = 4, alias_names=('s8'), general_purpose=True),
       Register(name='x25', size = 4, alias_names=('s9'), general_purpose=True),
       Register(name='x26', size = 4, alias_names=('s10'), general_purpose=True),
       Register(name='x27', size = 4, alias_names=('s11'), general_purpose=True),
       Register(name='x28', size = 4, alias_names=('t3'), general_purpose=True),
       Register(name='x29', size = 4, alias_names=('t4'), general_purpose=True),
       Register(name='x30', size = 4, alias_names=('t5'), general_purpose=True),
       Register(name='x31', size = 4, alias_names=('t6'), general_purpose=True),
    ]


register_arch([r'riscv32|riscv|em_riscv|em_riscv32'], 32, 'Iend_LE' , ArchRISCV)

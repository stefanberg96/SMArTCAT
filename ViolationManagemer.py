"""
This module manages violations.
"""

class ViolationManagemer():
    
    project = None
    violations = {}
    
    def __init__(self, project):
        self.project = project

    def registerProject(self, p):
        self.project = p
        
    def registerViolation(self, stmt, type, path):
        """
        the violation dict contains lists of violation objects, with violation addresses as the key to store them
        """
        
        bytes = ''.join(self.project.loader.memory.read_bytes(stmt.addr, stmt.len))
        cs = self.project.arch.capstone if stmt.delta == 0 else self.project.arch.capstone_thumb
        
        inst = cs.disasm(bytes, stmt.addr)[0]
        
        #this should only return a single disassembled instruction
        #for inst in cs.disasm(bytes, stmt.addr): mnemonic = angr.lifter.CapstoneInsn(d).mnemonic
        #print angr.lifter.CapstoneInsn(d);
        
        v = Violation(address, stmt, inst, type, path)
        if not self.violations.__contains__(address):
            self.violations[address] = [v]
        else:
            self.violations[address].append(v)
        
    def getViolationTypes(self, address):
        types = []
        for v in self.violations:
            types.append(v.type)
        return types
        
class Violation():
    """
    A simple class to represent timing-secure code violations
    """
    
    address = None
    instruction = None
    stmt = None
    type = None
    path = None
    
    def __init__(self, address, stmt, inst, path):
        self.address = address
        self.stmt = stmt
        self.inst = inst
        self.type = type
        self.path = path

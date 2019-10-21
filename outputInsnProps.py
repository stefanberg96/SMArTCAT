from __future__ import print_function
#import ../insnFormat
import settings
import properties

def func():
    import angr
    b = angr.Project("ARMCompiledInstructions")
    start = 0x105ec
    project = b
    cs = project.arch.capstone
    
    #we're performing double disassembling because the lifter is also doing it... probably not the most efficient thing... but it doesn't seem to be a bottleneck
    
    lastinsn = ""
    while(start <= 0x10d54):
        if start == 0x10c38:
            start += 8
        bytes = ''.join(project.loader.memory.read_bytes(start, 4))
        insn = next(cs.disasm(bytes, start))
        props = properties.Properties(insn)
        start += 4
        #print insn.insn_name()
        if props.format != None:
            f = printable(props.format)
            if props.canDualIssueAsYounger():
                d = "Dy"
            elif props.canDualIssueAsOlder():
                d = "Do"
            else:
                d = " "
            timett = props.timeTupleTuple()
            if timett != None:
                if timett[0] != None:
                    i = "%s" % timett[0][0]
                    cfi = "%s" % timett[0][1]
                if timett[1] != None:
                    l = "%s" % timett[1][0]
                    cfl = "%s" % timett[1][1]
            #TODO: else!!
            m = "+" if props.isMemInsn() else ""
            if props.accumulatorReg() != None:
                if "<ra>" in props.format:
                    a = "ra"
                elif "<rdlo>" in props.format:
                    a = "rdlo"
            else:
                a = ""
            fa = "+" if props.canForwardToAccumulator() else ""
            sb = "+" if props.canReceiveSemiBypass() else ""
            er = ""
            for k,ear in enumerate(props.earlyReg()):
                if k == 0:
                    er = regToFormreg(props.format, insn.reg_name(ear))
                else:
                    er += ", "+regToFormreg(props.format, insn.reg_name(ear))
            if er == "ERROR: sp":
                er = "sp"
            lt = ""
            for k,lat in enumerate(props.lateReg()):
                if k == 0:
                    lt = regToFormreg(props.format, insn.reg_name(lat[0])) + ": %d"%lat[1]
                else:
                    lt += ", "+regToFormreg(props.format, insn.reg_name(lat[0])) + ": %d"%lat[1]
            if lt != "" and "<registers>" in props.format:
                lt = "\\textless{}registers\\textgreater{}: 2"
            if insn.mnemonic == "swp":
                lt = ""
            if "<registers>" in props.format:
                i += "$^*$"
                l += "$^*$"
                cfi += "$^*$"
                cfl += "$^*$"
            line = "%s & %s & %s & %s & %s & %s & %s & %s & %s & %s & %s & %s \\\\" % (f,d,i,l,m,cfi,cfl,a,fa,sb,er,lt)
            if line != lastinsn:
                lastinsn = line
                if insn.mnemonic != "swpb":
                    print(line)
            import store
            if insn.insn_name() == "smlal":
                store.insn = insn
        
    
    
    
    #for f in insnFormat.formats:
    #    props = new Properties(
    #    line = printable(f)
        
def regToFormreg(format, reg):
    #print "%s: %s" % (format, reg)
    splitformat = format.split()
    i = 0
    j = 0
    while i<len(splitformat):
        if len(splitformat[i])>2 and "<r" in splitformat[i]:
            #print splitformat[i]
            j += 1
            #print j
            #print splitformat[i][1:2]
            #print splitformat[i][splitformat[i].find("<r")+2:splitformat[i].find("<r")+3]
            if ("%d" % j) == reg[1:2]:
                return splitformat[i][splitformat[i].find("<r"):splitformat[i].find("<r")+4].replace("<", "").replace(">", "") #"\\textless{}", "\\textgreater{}"
        i += 1
    return "ERROR: %s" % reg
        
def printable(fin):
    fout = fin
    fout = fout.replace("{", "\\{")
    fout = fout.replace("}", "\\}")
    fout = fout.replace("#", "\\#")
    fout = fout.replace("_", "\\_")
    fout = fout.replace("<", "\\textless{}")
    fout = fout.replace(">", "\\textgreater{}")
    return "\\texttt{%s}" % fout
    
class Instruction():
    """instruction properties"""
    def __init__(self, format):
        self.format = format
        
    def insn_name():
        return self.format
        

        
func()
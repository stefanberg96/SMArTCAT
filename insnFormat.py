from __future__ import print_function
import capstone as cap


def format(insn):
    subset = []
    namelen = len(insn.insn_name())
    rotationCodedConstant = False

    # step 1: find formats with matching insn_name
    for i in formats:
        if insn.insn_name() in i and (i[namelen:namelen+1] == " " or i[namelen:namelen+1] == "<"):
            subset.append((i, i.split(' ')))
    # print "first level contenders %s\n" % subset
    if len(subset) == 0:
        print("Warning: instruction \"%s %s\" did not match any format!" %
              (insn.mnemonic, insn.op_str))
        return None

    if len(subset) > 1:
        print("Warning: multiple instructions matched on this format %s" %(insn.mnemonic))

    bypass = False
    if len(subset) == 1 and insn.insn_name() in ['stm', 'stmib', 'stmdb', 'stmda', 'ldm', 'ldmib', 'ldmdb', 'ldmda', 'pop', 'push']:
        bypass = True

    if len(subset) == 0:
        print("Warning: instruction \"%s %s\" did not match any format!" %
              (insn.mnemonic, insn.op_str))
        return None
    else:
        # workarounds for formats which were somehow not identified correctly
        if len(subset) > 1:
            if insn.insn_name() == "smlal":
                if insn.mnemonic[5:6] != "B" and insn.mnemonic[5:6] != "T":
                    return subset[0][0]
                else:
                    return subset[1][0]
            else:
                print("Warning: instruction \"%s %s\" matches multiple formats!" % (
                    insn.mnemonic, insn.op_str))
                print(subset)
        return subset[0][0]


def test():
    import tool
    print("")
    import store
    insn = store.insn
    print("last insn: %s %s" % (insn.mnemonic, insn.op_str))
    print("")
    print(format(insn))
    return insn


# insn = testo)
formats = []
r=cap.CS_AC_READ
w=cap.CS_AC_WRITE
branch = {"beq": [r,r,r], "bne":[r,r,r], "blt":[r,r,r], "bge":[r,r,r],"bltu":[r,r,r],"bgeu":[r,r,r], "beqz":[r,r], "bnez":[r,r], "blez"[r,r],"bgez":[r,r],"bltz":[r,r],"bgtz":[r,r], "bgt":[r,r,r],"ble":[r,r,r],"bgtu":[r,r,r],"bleu":[r,r,r]}
jump = {"j": [r],"jr":[r], "jal":[r, r],"jalr":[w, r, r]}
load = {"lb":[w,r], "lh":[w,r], "lbu":[w,r], "lhu":[w,r], "lw":[w,r]}
store = {"sb":[r,w], "sh":[r,w],"sw":[r,w]}
non_default_rw = {"lui":[w,r],"auipc":[w,r], "li":[w,r],"mv":[w,r],"not":[w.r],"neg":[w,r],"seqz":[w,r], "snez":[w,r],"sltz":[w,r], "sgtz":[w,r]}

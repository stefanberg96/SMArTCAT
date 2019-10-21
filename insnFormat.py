from __future__ import print_function
import capstone as cap

def format(insn):
    subset = []
    namelen = len(insn.insn_name())
    rotationCodedConstant = False
    
    #step 1: find formats with matching insn_name
    for i in formats:
        if insn.insn_name() in i and (i[namelen:namelen+1] == " " or i[namelen:namelen+1] == "<"):
            subset.append((i, i.split(' ')))
    #print "first level contenders %s\n" % subset
    if len(subset) == 0:
        print("Warning: instruction \"%s %s\" did not match any format!" % (insn.mnemonic, insn.op_str))
        return None
        
    bypass = False
    if len(subset) == 1 and insn.insn_name() in ['stm', 'stmib', 'stmdb', 'stmda', 'ldm', 'ldmib', 'ldmdb', 'ldmda', 'pop', 'push']:
        bypass = True
    
    if not bypass:
        #step2: filter out formats with wrong operand types
        leftoverContenders = []
        MemOperandFound = False
        memOpIndex = -1
        immediateProcessed = False
        for k, o in enumerate(insn.operands):
            if (o.type == cap.CS_OP_REG): #register
                for c in subset:
                    try:
                        if len(c[1]) > k+1 and c[1][k+1][0:2] == "<r":
                            leftoverContenders.append(c)
                    except Exception as e:
                        True;#do nothing
            if (o.type == 2): #immediate or constant
                processedLatest = False
                for c in subset:
                    if not MemOperandFound and len(c[1]) > k+1 and (c[1][k+1][0:1] == "#" or c[1][k+1] == "<label>"):
                        leftoverContenders.append(c)
                        immediateProcessed = True
                        processedLatest = True
                    elif MemOperandFound and c[1][-1][0:1] == "#" and "]" not in c[1][-1]: #memory operands are sometimes followed by immediate operands
                        leftoverContenders.append(c)
                        immediateProcessed = True
                        processedLatest = True
                if not processedLatest and immediateProcessed: #couldn't find a second immediate value but couldn't find a match for this instruction... that means this instruction has a constant construct from 2 constants.
                    leftoverContenders.append(c)
                    rotationCodedConstant = True
            if (o.type == cap.CS_OP_MEM): #memory
                for c in subset:
                    if len(c[1]) > k+1 and c[1][k+1][0:1] == "[":
                        leftoverContenders.append(c)
                        MemOperandFound = True
                        memOpIndex = k
            subset = leftoverContenders
            leftoverContenders = []
            #print "contenders after iteration %d %s\n" % (k, subset)
        
            
        #step3: filter out formats with no/wrong shift format:
            #immediate shifts are always the last operands and have format <shift>
            #register shifts have format <type> <Rs> and are also the last part of the format. These have cs shift type >= 6
        if insn.operands[len(insn.operands)-1].shift.type != 0: #shift is instruction
            if insn.operands[len(insn.operands)-1].shift.type < 6: #immediate shift
                for c in subset:
                    if "<shift>" in c[1][len(c[1])-1] or (insn.insn_name() in ["lsl", "lsr", "asr", "ror", "rrx"] and len(insn.operands)+2 == len(c[1]) and c[1][len(c[1])-1][0:1] == "#"):
                        leftoverContenders.append(c)
            elif insn.operands[len(insn.operands)-1].shift.type >= 6: #register shift
                for c in subset:
                    if "<rs>" in c[1][len(c[1])-1] or (insn.insn_name() in ["lsl", "lsr", "asr", "ror", "rrx"] and len(insn.operands)+2 == len(c[1]) and c[1][len(c[1])-1][0:1] == "<"):
                        leftoverContenders.append(c)
        else:
            for c in subset:
                if "<rs>"  not in c[1][len(c[1])-1] and "<shift>" not in c[1][len(c[1])-1]:
                    leftoverContenders.append(c)
        subset = leftoverContenders
        leftoverContenders = []
        #print "contenders after shift filtering: %s\n" % subset
            
        #step4: filter out formats with wrong memory format
        if MemOperandFound:
            #first memory operand (base) is _always_ a register, so no need to validate
            #formats have either a displacement, OR an (index with possibly a shift)
            if insn.operands[memOpIndex].mem.disp != 0: #displacement
                for c in subset:
                    if len(c[1]) > memOpIndex+2 and c[1][memOpIndex+2][0:1] == "#" and "]" in c[1][memOpIndex+2]:
                        leftoverContenders.append(c)
            elif insn.operands[memOpIndex].mem.index != 0: #index
                for c in subset:
                    if len(c[1]) > memOpIndex+2 and c[1][memOpIndex+2][0:1] == "+":
                        if insn.operands[memOpIndex].mem.lshift == 0 and insn.operands[memOpIndex].shift.type == 0: #index but no shift
                            if "]" in c[1][memOpIndex+2]:
                                leftoverContenders.append(c)
                        elif len(c[1]) > memOpIndex+3 and "<shift>" in c[1][memOpIndex+3]:
                            leftoverContenders.append(c)
            else: #no displacement, no index, or postindexed displacement
                for c in subset:
                    if "]" in c[1][memOpIndex+1] and len(c[1]) == len(insn.operands)+1:
                        leftoverContenders.append(c)
        else:
            for c in subset:
                if "[" not in c[0]:
                    leftoverContenders.append(c)
        subset = leftoverContenders
        leftoverContenders = []
        #print "contenders after memory filtering: %s\n" % subset
        
    # Rotate right: 0b1001 --> 0b1100
    ror = lambda val, r_bits, max_bits: \
        ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
        (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))
        
    #this is a hack to allow the rest of the tool to properly process this instruction
    if rotationCodedConstant:
        for k,i in enumerate(insn.operands):
            if i.type == 2: #constant
                #update this value
                insn.operands[k].value.imm = ror(i.imm,insn.operands[k+1].imm,32)
                #drop last operand
                del insn.operands[k+1]
                break
        
    if len(subset) == 0:
        print("Warning: instruction \"%s %s\" did not match any format!" % (insn.mnemonic, insn.op_str))
        return None
    else:
        #workarounds for formats which were somehow not identified correctly
        if len(subset) > 1:
            if insn.insn_name() == "smlal":
                if insn.mnemonic[5:6] != "B" and insn.mnemonic[5:6] != "T":
                    return subset[0][0]
                else:
                    return subset[1][0]
            else: 
                print("Warning: instruction \"%s %s\" matches multiple formats!" % (insn.mnemonic, insn.op_str))
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
    
#insn = test()

formats = ["adcs <rd>, <rn>, #<const>", "adc<c> <rd>, <rn>, #<const>", "adcs <rd>, <rn>, <rm>, <shift>", "adc<c> <rd>, <rn>, <rm>, <shift>", "adcs <rd>, <rn>, <rm>", "adc<c> <rd>, <rn>, <rm>", "adcs <rd>, <rn>, <rm>, <type> <rs>", "adc<c> <rd>, <rn>, <rm>, <type> <rs>", "adds <rd>, <rn>, #<const>", "add<c> <rd>, <rn>, #<const>", "adds <rd>, <rn>, <rm>, <shift>", "adds <rd>, <rn>, <rm>", "add<c> <rd>, <rn>, <rm>, <shift>", "add<c> <rd>, <rn>, <rm>", "adds <rd>, <rn>, <rm>, <type> <rs>", "add<c> <rd>, <rn>, <rm>, <type> <rs>", "adds <rd>, sp, #<const>", "add<c> <rd>, sp, #<const>", "adds <rd>, sp, <rm>, <shift>", "adds <rd>, sp, <rm>", "add<c> <rd>, sp, <rm>, <shift>", "add<c> <rd>, sp, <rm>", "adr<c> <rd>, <label>", "ands <rd>, <rn>, #<const>", "and<c> <rd>, <rn>, #<const>", "ands <rd>, <rn>, <rm>, <shift>", "ands <rd>, <rn>, <rm>", "and<c> <rd>, <rn>, <rm>, <shift>", "and<c> <rd>, <rn>, <rm>", "ands <rd>, <rn>, <rm>, <type> <rs>", "and<c> <rd>, <rn>, <rm>, <type> <rs>", "asrs <rd>, <rm>, #<imm>", "asr<c> <rd>, <rm>, #<imm>", "asrs <rd>, <rn>, <rm>", "asr<c> <rd>, <rn>, <rm>", "b<c> <label>", "bfi<c> <rd>, <rn>, #<lsb>, #<width>", "bics <rd>, <rn>, #<const>", "bic<c> <rd>, <rn>, #<const>", "bics <rd>, <rn>, <rm>, <shift>", "bics <rd>, <rn>, <rm>", "bic<c> <rd>, <rn>, <rm>, <shift>", "bic<c> <rd>, <rn>, <rm>", "bics <rd>, <rn>, <rm>, <type> <rs>", "bic<c> <rd>, <rn>, <rm>, <type> <rs>", "bkpt #<imm>", "bl<c> <label>", "blx<c> <rm>", "bx<c> <rm>", "bxj<c> <rm>", "clz<c> <rd>, <rm>", "cmn<c> <rn>, #<const>", "cmn<c> <rn>, <rm>, <shift>", "cmn<c> <rn>, <rm>", "cmn<c> <rn>, <rm>, <type> <rs>", "cmp<c> <rn>, #<const>", "cmp<c> <rn>, <rm>, <shift>", "cmp<c> <rn>, <rm>", "cmp<c> <rn>, <rm>, <type> <rs>", "dbg<c> #<option>", "dmb <option>", "dsb <option>", "eors <rd>, <rn>, #<const>", "eor<c> <rd>, <rn>, #<const>", "eors <rd>, <rn>, <rm>, <shift>", "eors <rd>, <rn>, <rm>", "eor<c> <rd>, <rn>, <rm>, <shift>", "eor<c> <rd>, <rn>, <rm>", "eors <rd>, <rn>, <rm>, <type> <rs>", "eor<c> <rd>, <rn>, <rm>, <type> <rs>", "isb <option>", "ldm<c> <rn>{!}, <registers>", "ldmda<c> <rn>{!}, <registers>", "ldmdb<c> <rn>{!}, <registers>", "ldmib<c> <rn>{!}, <registers>", "ldr<c> <rt>, [<rn>, #+/-<imm>]", "ldr<c> <rt>, [<rn>]", "ldr<c> <rt>, <label>", "ldr<c> <rt>, [<rn>, +/-<rm>, <shift>]{!}", "ldr<c> <rt>, [<rn>, +/-<rm>]{!}", "ldr<c> <rt>, [<rn>], #+/-<imm>", "ldrb<c> <rt>, [<rn>, #+/-<imm>]", "ldrb<c> <rt>, [<rn>]", "ldrb<c> <rt>, <label>", "ldrb<c> <rt>, [<rn>, +/-<rm>, <shift>]{!}", "ldrb<c> <rt>, [<rn>, +/-<rm>]{!}", "ldrb<c> <rt>, [<rn>], #+/-<imm>", "ldrbt<c> <rt>, [<rn>], #+/-<imm>", "ldrd<c> <rt>, <rt2>, [<rn>, #+/-<imm>]", "ldrd<c> <rt>, <rt2>, [<rn>]", "ldrd<c> <rt>, <rt2>, <label>", "ldrd<c> <rt>, <rt2>, [<rn>, +/-<rm>]{!}", "ldrd<c> <rt>, <rt2>, [<rn>], #+/-<imm>", "ldrex<c> <rt>, [<rn>]", "ldrexb<c> <rt>, [<rn>]", "ldrexd<c> <rt>, <rt2>, [<rn>]", "ldrexh<c> <rt>, [<rn>]", "ldrh<c> <rt>, [<rn>, #+/-<imm>]", "ldrh<c> <rt>, [<rn>]", "ldrh<c> <rt>, <label>", "ldrh<c> <rt>, [<rn>, +/-<rm>]{!}", "ldrh<c> <rt>, [<rn>], #+/-<imm>", "ldrht<c> <rt>, [<rn>], #+/-<imm>", "ldrht<c> <rt>, [<rn>] ", "ldrsb<c> <rt>, [<rn>, #+/-<imm>]", "ldrsb<c> <rt>, [<rn>]", "ldrsb<c> <rt>, <label>", "ldrsb<c> <rt>, [<rn>, +/-<rm>]{!}", "ldrsb<c> <rt>, [<rn>], #+/-<imm>", "ldrsbt<c> <rt>, [<rn>], #+/-<imm>", "ldrsbt<c> <rt>, [<rn>] ", "ldrsh<c> <rt>, [<rn>, #+/-<imm>]", "ldrsh<c> <rt>, [<rn>]", "ldrsh<c> <rt>, <label>", "ldrsh<c> <rt>, [<rn>, +/-<rm>]{!}", "ldrsh<c> <rt>, [<rn>], #+/-<imm>", "ldrsht<c> <rt>, [<rn>], #+/-<imm>", "ldrsht<c> <rt>, [<rn>] ", "ldrt<c> <rt>, [<rn>], #+/-<imm>", "ldrt<c> <rt>, [<rn>] ", "lsls <rd>, <rm>, #<imm>", "lsl<c> <rd>, <rm>, #<imm>", "lsls <rd>, <rn>, <rm>", "lsl<c> <rd>, <rn>, <rm>", "lsrs <rd>, <rm>, #<imm>", "lsr<c> <rd>, <rm>, #<imm>", "lsrs <rd>, <rn>, <rm>", "lsr<c> <rd>, <rn>, <rm>", "mlas <rd>, <rn>, <rm>, <ra>", "mla<c> <rd>, <rn>, <rm>, <ra>", "mls<c> <rd>, <rn>, <rm>, <ra>", "movs <rd>, #<const>", "mov<c> <rd>, #<const>", "movs <rd>, <rm>", "mov<c> <rd>, <rm>", "mrs<c> <rd>, <spec_reg>", "msr<c> <spec_reg>, #<const>", "msr<c> <spec_reg>, <rn>", "muls <rd>, <rn>, <rm>", "mul<c> <rd>, <rn>, <rm>", "mvns <rd>, #<const>", "mvn<c> <rd>, #<const>", "mvns <rd>, <rm>, <shift>", "mvns <rd>, <rm>", "mvn<c> <rd>, <rm>, <shift>", "mvn<c> <rd>, <rm>", "mvns <rd>, <rm>, <type> <rs>", "mvn<c> <rd>, <rm>, <type> <rs>", "nop<c>", "orrs <rd>, <rn>, #<const>", "orr<c> <rd>, <rn>, #<const>", "orrs <rd>, <rn>, <rm>, <shift>", "orrs <rd>, <rn>, <rm>", "orr<c> <rd>, <rn>, <rm>, <shift>", "orr<c> <rd>, <rn>, <rm>", "orrs <rd>, <rn>, <rm>, <type> <rs>", "orr<c> <rd>, <rn>, <rm>, <type> <rs>", "pkhbt<c> <rd>, <rn>, <rm>, lsl #<imm>", "pkhbt<c> <rd>, <rn>, <rm>", "pld <label>", "pop<c> <registers>", "push<c> <registers>", "qadd<c> <rd>, <rm>, <rn>", "qadd16<c> <rd>, <rn>, <rm>", "qadd8<c> <rd>, <rn>, <rm>", "qasx<c> <rd>, <rn>, <rm>", "qdadd<c> <rd>, <rm>, <rn>", "qdsub<c> <rd>, <rm>, <rn>", "qsax<c> <rd>, <rn>, <rm>", "qsub<c> <rd>, <rm>, <rn>", "qsub16<c> <rd>, <rn>, <rm>", "qsub8<c> <rd>, <rn>, <rm>", "rbit<c> <rd>, <rm>", "rev<c> <rd>, <rm>", "rev16<c> <rd>, <rm>", "revsh<c> <rd>, <rm>", "rors <rd>, <rm>, #<imm>", "ror<c> <rd>, <rm>, #<imm>", "rors <rd>, <rn>, <rm>", "ror<c> <rd>, <rn>, <rm>", "rrxs <rd>, <rm>", "rrx<c> <rd>, <rm>", "rsbs <rd>, <rn>, #<const>", "rsb<c> <rd>, <rn>, #<const>", "rsbs <rd>, <rn>, <rm>, <shift>", "rsbs <rd>, <rn>, <rm>", "rsb<c> <rd>, <rn>, <rm>, <shift>", "rsb<c> <rd>, <rn>, <rm>", "rsbs <rd>, <rn>, <rm>, <type> <rs>", "rsb<c> <rd>, <rn>, <rm>, <type> <rs>", "rscs <rd>, <rn>, #<const>", "rsc<c> <rd>, <rn>, #<const>", "rscs <rd>, <rn>, <rm>, <shift>", "rscs <rd>, <rn>, <rm>", "rsc<c> <rd>, <rn>, <rm>, <shift>", "rsc<c> <rd>, <rn>, <rm>", "rscs <rd>, <rn>, <rm>, <type> <rs>", "rsc<c> <rd>, <rn>, <rm>, <type> <rs>", "sadd16<c> <rd>, <rn>, <rm>", "sadd8<c> <rd>, <rn>, <rm>", "sasx<c> <rd>, <rn>, <rm>", "sbcs <rd>, <rn>, #<const>", "sbc<c> <rd>, <rn>, #<const>", "sbcs <rd>, <rn>, <rm>, <shift>", "sbcs <rd>, <rn>, <rm>", "sbc<c> <rd>, <rn>, <rm>, <shift>", "sbc<c> <rd>, <rn>, <rm>", "sbcs <rd>, <rn>, <rm>, <type> <rs>", "sbc<c> <rd>, <rn>, <rm>, <type> <rs>", "sbfx<c> <rd>, <rn>, #<lsb>, #<width>", "sel<c> <rd>, <rn>, <rm>", "setend <endian_specifier>", "shadd16<c> <rd>, <rn>, <rm>", "shadd8<c> <rd>, <rn>, <rm>", "shasx<c> <rd>, <rn>, <rm>", "shsax<c> <rd>, <rn>, <rm>", "shsub16<c> <rd>, <rn>, <rm>", "shsub8<c> <rd>, <rn>, <rm>", "smla<x><y><c> <rd>, <rn>, <rm>, <ra>", "smlad{x}<c> <rd>, <rn>, <rm>, <ra>", "smlals <rdlo>, <rdhi>, <rn>, <rm>", "smlal<c> <rdlo>, <rdhi>, <rn>, <rm>", "smlal<x><y><c> <rdlo>, <rdhi>, <rn>, <rm>", "smlald{x}<c> <rdlo>, <rdhi>, <rn>, <rm>", "smlaw<y><c> <rd>, <rn>, <rm>, <ra>", "smlsd{x}<c> <rd>, <rn>, <rm>, <ra>", "smlsld{x}<c> <rdlo>, <rdhi>, <rn>, <rm>", "smmla{r}<c> <rd>, <rn>, <rm>, <ra>", "smmls{r}<c> <rd>, <rn>, <rm>, <ra>", "smmul{r}<c> <rd>, <rn>, <rm>", "smuad{x}<c> <rd>, <rn>, <rm>", "smul<x><y><c> <rd>, <rn>, <rm>", "smulls <rdlo>, <rdhi>, <rn>, <rm>", "smull<c> <rdlo>, <rdhi>, <rn>, <rm>", "smulw<y><c> <rd>, <rn>, <rm>", "smusd{x}<c> <rd>, <rn>, <rm>", "ssat<c> <rd>, #<imm>, <rn>, <shift>", "ssat<c> <rd>, #<imm>, <rn>", "ssat16<c> <rd>, #<imm>, <rn>", "ssax<c> <rd>, <rn>, <rm>", "ssub16<c> <rd>, <rn>, <rm>", "ssub8<c> <rd>, <rn>, <rm>", "stm<c> <rn>{!}, <registers>", "stmda<c> <rn>{!}, <registers>", "stmdb<c> <rn>{!}, <registers>", "stmib<c> <rn>{!}, <registers>", "str<c> <rt>, [<rn>, #+/-<imm>]", "str<c> <rt>, [<rn>]", "str<c> <rt>, [<rn>, +/-<rm>, <shift>]{!}", "str<c> <rt>, [<rn>, +/-<rm>]{!}", "str<c> <rt>, [<rn>], #+/-<imm>", "strb<c> <rt>, [<rn>, #+/-<imm>]", "strb<c> <rt>, [<rn>]", "strb<c> <rt>, [<rn>, +/-<rm>, <shift>]{!}", "strb<c> <rt>, [<rn>, +/-<rm>]{!}", "strb<c> <rt>, [<rn>], #+/-<imm>", "strbt<c> <rt>, [<rn>], #+/-<imm>", "strd<c> <rt>, <rt2>, [<rn>, #+/-<imm>]", "strd<c> <rt>, <rt2>, [<rn>]", "strd<c> <rt>, <rt2>, [<rn>, +/-<rm>]{!}", "strd<c> <rt>, <rt2>, [<rn>], #+/-<imm>", "strex<c> <rd>, <rt>, [<rn>]", "strexb<c> <rd>, <rt>, [<rn>]", "strexd<c> <rd>, <rt>, <rt2>, [<rn>]", "strexh<c> <rd>, <rt>, [<rn>]", "strh<c> <rt>, [<rn>]", "strh<c> <rt>, [<rn>, #+/-<imm>]", "strh<c> <rt>, [<rn>, +/-<rm>]{!}", "strh<c> <rt>, [<rn>], #+/-<imm>", "strht<c> <rt>, [<rn>], #+/-<imm>", "strht<c> <rt>, [<rn>] ", "strt<c> <rt>, [<rn>], #+/-<imm>", "strt<c> <rt>, [<rn>] ", "subs <rd>, <rn>, #<const>", "sub<c> <rd>, <rn>, #<const>", "subs <rd>, <rn>, <rm>, <shift>", "subs <rd>, <rn>, <rm>", "sub<c> <rd>, <rn>, <rm>, <shift>", "sub<c> <rd>, <rn>, <rm>", "subs <rd>, <rn>, <rm>, <type> <rs>", "sub<c> <rd>, <rn>, <rm>, <type> <rs>", "subs <rd>, sp, #<const>", "sub<c> <rd>, sp, #<const>", "subs <rd>, sp, <rm>, <shift>", "subs <rd>, sp, <rm>", "sub<c> <rd>, sp, <rm>, <shift>", "sub<c> <rd>, sp, <rm>", "svc<c> #<imm>", "swpb<c> <rt>, <rt2>, [<rn>]", "swp<c> <rt>, <rt2>, [<rn>]", "sxtab<c> <rd>, <rn>, <rm>", "sxtab16<c> <rd>, <rn>, <rm>", "sxtah<c> <rd>, <rn>, <rm>", "sxtb<c> <rd>, <rm>", "sxtb16<c> <rd>, <rm>", "sxth<c> <rd>, <rm>", "teq<c> <rn>, #<const>", "teq<c> <rn>, <rm>, <shift>", "teq<c> <rn>, <rm>", "teq<c> <rn>, <rm>, <type> <rs>", "tst<c> <rn>, #<const>", "tst<c> <rn>, <rm>, <shift>", "tst<c> <rn>, <rm>", "tst<c> <rn>, <rm>, <type> <rs>", "uadd16<c> <rd>, <rn>, <rm>", "uadd8<c> <rd>, <rn>, <rm>", "uasx<c> <rd>, <rn>, <rm>", "ubfx<c> <rd>, <rn>, #<lsb>, #<width>", "uhadd16<c> <rd>, <rn>, <rm>", "uhadd8<c> <rd>, <rn>, <rm>", "uhasx<c> <rd>, <rn>, <rm>", "uhsax<c> <rd>, <rn>, <rm>", "uhsub16<c> <rd>, <rn>, <rm>", "uhsub8<c> <rd>, <rn>, <rm>", "umaal<c> <rdlo>, <rdhi>, <rn>, <rm>", "umlals <rdlo>, <rdhi>, <rn>, <rm>", "umlal<c> <rdlo>, <rdhi>, <rn>, <rm>", "umulls <rdlo>, <rdhi>, <rn>, <rm>", "umull<c> <rdlo>, <rdhi>, <rn>, <rm>", "uqadd16<c> <rd>, <rn>, <rm>", "uqadd8<c> <rd>, <rn>, <rm>", "uqasx<c> <rd>, <rn>, <rm>", "uqsax<c> <rd>, <rn>, <rm>", "uqsub16<c> <rd>, <rn>, <rm>", "uqsub8<c> <rd>, <rn>, <rm>", "usad8<c> <rd>, <rn>, <rm>", "usada8<c> <rd>, <rn>, <rm>, <ra>", "usat<c> <rd>, #<imm>, <rn>, <shift>", "usat<c> <rd>, #<imm>, <rn>", "usat16<c> <rd>, #<imm>, <rn>", "usax<c> <rd>, <rn>, <rm>", "usub16<c> <rd>, <rn>, <rm>", "usub8<c> <rd>, <rn>, <rm>", "uxtab<c> <rd>, <rn>, <rm>", "uxtab16<c> <rd>, <rn>, <rm>", "uxtah<c> <rd>, <rn>, <rm>", "uxtb<c> <rd>, <rm>", "uxtb16<c> <rd>, <rm>", "uxth<c> <rd>, <rm>"]
#all rotation instructions (this encoding actually doesn't seem to be allowed in ARM A1), "uxtab16<c> <rd>, <rn>, <rm>, <rotation>", "uxth<c> <rd>, <rm>, <rotation>", "sxtb16<c> <rd>, <rm>, <rotation>", "sxtab<c> <rd>, <rn>, <rm>, <rotation>", "sxtb<c> <rd>, <rm>, <rotation>", "uxtb16<c> <rd>, <rm>, <rotation>", "uxtab<c> <rd>, <rn>, <rm>, <rotation>", "sxtab16<c> <rd>, <rn>, <rm>, <rotation>", "sxth<c> <rd>, <rm>, <rotation>", "sxtah<c> <rd>, <rn>, <rm>, <rotation>", "uxtah<c> <rd>, <rn>, <rm>, <rotation>", "uxtb<c> <rd>, <rm>, <rotation>"
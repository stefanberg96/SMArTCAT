from __future__ import print_function
import claripy

#todo: say an operation contains more than two operands (e.g. __add__(a,b,s,c)), it should be reduced to __add__(k,s)
#todo: it would be nice if we can change order of same-level operations (+/-) to simplify expressions futher.
def mergeFreeAsts(ast, nonfree):
    """
    merges ast's first child ast of depth larger than 1, not containing the variable nonfree, into a new symbol k.
    returns a tuple contain the ast with the child ast replaced by k, the symbol k, and the old subast which was replaced by k.
    """
    for c in list(ast.recursive_children_asts):
        #print "starting subrun"
        if (not c.variables.__contains__(nonfree.args[0])) and c.length != None and c.depth > 1:
            #print c
            subAst = c
            k = claripy.BVS('k', c.length)
            ast = ast.replace(c,k)
            return (ast,k,subAst)
    return False

def mergeFreeIteratively(ast, nonfree):
    """
    returns a tuple of a new ast with all expressions not containing the variable nonfree merged into a new symbol k, and the constraints on k and subK's
    """
    loop = True
    kConstraints = claripy.true
    while(loop):
        #print "starting iterative run"
        #print ast
        merged = mergeFreeAsts(ast, nonfree)
        if not merged:
            loop = False
        else:
            kConstraints = claripy.And(kConstraints, merged[1] == merged[2])
            ast = merged[0]
    #print "done"
    return claripy.And(ast,kConstraints)

#currently assumes asts of the format a op b rel c, or a rel b op c. where either a or b contains s.
def free(ast, nonfree):
    """
    attempts to isolate s on one side of the relation, by moving arguments to the other side of the expression
    """
    #freeup determines whether the operation is on the left (0) or right (1) parameter of the relation
    if (ast.args[0].variables.__contains__(nonfree.args[0])):
        freeup = 0
    else:
        freeup = 1
    op = ast.args[freeup].op
    if (op == '__mul__'):
        #TODO: this doesn't take integer over/underflows into account!
        #subAst determines whether to _move_ the a part(0) of a * b, or the b part(1)
        subAst = 1 if ast.args[freeup].args[0].variables.__contains__(nonfree.args[0]) else 0
        newAst = ast.args[1-freeup]/ast.args[freeup].args[subAst] + (ast.args[1-freeup] % ast.args[freeup].args[subAst])
        ast = ast.replace(ast.args[freeup], ast.args[freeup].args[1-subAst])
        ast = ast.replace(ast.args[1-freeup], newAst)
        return ast
    elif (op == '__div__'):
        #TODO: this doesn't take integer over/underflows into account! (only matters for unsigned inequalities)
        #TODO: this operation is not commutative
        #subAst determines whether to _move_ the a part(0) of a / b, or the b part(1)
        subAst = 1 if ast.args[freeup].args[0].variables.__contains__(nonfree.args[0]) else 0
        if (subAst == 1):
            #c = a/b  -->  a = bc + a % b
            newAst = ast.args[1-freeup]*ast.args[freeup].args[subAst] + ((ast.args[freeup].args[1-subAst]) % ast.args[freeup].args[subAst])
            ast = ast.replace(ast.args[freeup], ast.args[freeup].args[1-subAst])
            ast = ast.replace(ast.args[1-freeup], newAst)
        else:
            if ast.args[freeup].op == '__eq__':
                #c = a/b  -->  bc + a % b = a  -->  a % b = a - bc --> (a = kb + a-bc --> c = k ), 0 <= a-bc < b, k=floor(a/b) --> (0 <= a-bc --> b <= a/c) ^ (a-bc < b --> b+bc > a)
                c = ast.args[1-freeup]
                s = ast.args[freeup].args[subAst]
                k = ast.args[freeup].args[1-subAst]
                #c = k/s -> ((b <= a/c ^ c>0) v (b >= a/c ^ c<0)) ^ b+bc > a
                newAst = claripy.And(claripy.Or(claripy.And(b <= a/c, c>0), claripy.And(b >= a/c, c<0)), b+bc > a)
                print("not sure if this 'reduction' is actually meaningful: freed s from a = b/s, possibly lost precision")
                ast = ast.replace(ast, newAst)
            else:
                #TODO: implement scenarios for other relations than equality.
                print("unimplemented translation a R b/c for R not an equality relation")
        return ast
    elif (op == '__add__'):
        #TODO: this doesn't take integer over/underflows into account! (only matters for unsigned inequalities)
        subAst = 1 if ast.args[freeup].args[0].variables.__contains__(nonfree.args[0]) else 0
        newAst = ast.args[1-freeup] - ast.args[freeup].args[subAst]
        ast = ast.replace(ast.args[freeup], ast.args[freeup].args[1-subAst])
        ast = ast.replace(ast.args[1-freeup], newAst)
        return ast
    elif (op == '__sub__'):
        #TODO: this doesn't take integer over/underflows into account! (only matters for unsigned inequalities)
        #secret determines whether a is secret (0), or b is secret (1), in a - b
        secret = 0 if ast.args[freeup].args[0].variables.__contains__(nonfree.args[0]) else 1
        c = ast.args[1-freeup]
        op = ast.args[freeup].op
        if (secret == 0):
            # c rel a(s) - b -> c + b rel a
            newAst = ast.args[1-freeup] + ast.args[freeup].args[1-secret] # c + b
            ast = ast.replace(ast.args[freeup], ast.args[freeup].args[secret])
            ast = ast.replace(ast.args[1-freeup], newAst)
        else:
            #secret determines whether a is secret (0), or b is secret (1), in a - b
            # c rel a - b(s) -> b rel a - c
            a = ast.args[freeup].args[1-secret]
            b = ast.args[freeup].args[secret]
            newAst = a - c
            ast = ast.replace(ast.args[1-freeup], b)
            ast = ast.replace(ast.args[freeup], newAst)
        return ast
    else:
        #no processing yet
        return ast

#TODO: add ast self to the list of asts to iterate through (so we can call it on a relation ast directly)
#relations are either: __eq__, __ne__, __ge__, __gt__, __le__, __lt__, SGE, SGT, SLE, SLT, UGE, UGT, ULE, ULT
def extractRelations(ast, nonfree):
    """
    extract relations on the nonfree variable from the ast, returns a list of those relations
    TODO: include extra constraints for those relations (e.g. when a relation is extracted from an if statement
    """
    relations = {"__eq__", "__ne__", "__ge__", "__gt__", "__le__", "__lt__", "SGE", "SGT", "SLE", "SLT", "UGE", "UGT", "ULE", "ULT"}
    results = []
    ast = ast.ite_excavated
    for a in ast.recursive_children_asts:
        if relations.__contains__(a.op) and a.variables.__contains__(nonfree.args[0]):
            results.append(a)
    return results

#TODO: check whether this is actually the same as .reversed
def mergeReversed(ast, symbol):
    """
    processed symbols which are reversed are often split up in per byte concats like so: s[7:0] .. s[15:8] .. s[23:16] .. s[31:24].
    however this isn't very readable, so let's just merge it to claripy.reversed(s)
    """
    #concattedSymbol = symbol[symbol.length-1:symbol.length-8]
    concattedSymbol = symbol[7:0]
    #for i in range(symbol.length-9,0,-8):
    for i in range(15,symbol.length,8):
        concattedSymbol = concattedSymbol.concat(symbol[i:i-7])
    #print concattedSymbol
    #print symbol.reversed
    return ast.replace(concattedSymbol, symbol.reversed)

def deobfuscateSignComparisons(ast, solver):
    """
    angr tends to evaluate ast's signedness by extracting the signbit. This limits the possibility to move arguments around relations, so this function deobfuscates this comparison by replacing the sign comparison with an inequality to 0.
    """
    astsToAnalyze = list(ast.recursive_children_asts)
    astsToAnalyze.append(ast)
    #we're currently changing childs as we loop through them. not sure if this is safe.
    for c in astsToAnalyze:
        if c.op == '__eq__' and c.args[0].op == 'Extract' and c.args[0].args[0] == 31 and c.args[0].args[1] == 31:
            #print "identified obfuscated sign comparison"
            # (left handside extracts, right handside contains 0 or 1)
            if not solver.solution(c.args[1], 1):
                inequality = c.args[0].args[2].SGE(0)
                ast = ast.replace(c,inequality)
            elif not solver.solution(c.args[1], 0):
                inequality = c.args[0].args[2].SLT(0)
                ast = ast.replace(c,inequality)
            #else: raise error / don't replace / eval the other side (this may sometimes be an if statement)
        elif c.op == '__eq__' and c.args[1].op == 'Extract' and c.args[1].args[0] == 31 and c.args[1].args[1] == 31:
            # (right handside extracts, left handside contains 0 or 1)
            if not solver.solution(c.args[0], 1):
                inequality = c.args[1].args[2].SGE(0)
                ast = ast.replace(c,inequality)
            elif not solver.solution(c.args[0], 0):
                inequality = c.args[1].args[2].SLT(0)
                ast = ast.replace(c,inequality)
            #else: raise error / don't replace / eval the other side (this may sometimes be an if statement)
    return ast
    
#fetches a constraint on k from ast which doesn't contain secret, so basically the descriptive constraint on k
def kDescription(ast, k, secret):
    if type(k) is str:
        import analysisUtils
        k = analysisUtils.stringToVar(k, [ast])
    for k in extractRelations(ast, k):
        if not k.variables.__contains__(secret.args[0]):
            return k

#1: freeup variables in each constraint to gain as limited relations s E k as possible.
#2: duplicate constraints to C and C'
#3: add s!=s', p==p', t!=t'
#4: compute dynamic range.
#5: add s E k and s' !E k   ( limit k to max and min s, s'? (not sure if actually needed))
#6: see if t already concretized
#7: limit s and s' to edge cases near k (symbolically).
#       -> edge cases:  for E is < >  etc, use minmax.
#                       for E is = !=, add another C" and make s" = s+q, then minimize q
#8: see if t already concretized
#9: find options for k (number of options for k is basically the accuracy of the side channel)
#10: concretize k
#11: see if t already concretized
#12: if t not yet concretized, concretize it ourselves. (is this actually a valid step? I think waiting for it to concretize is the only method we have to know that the relation applies to all t! (possibly this may only apply to some scenario's)) (one reason t might not concretize though is that k, pubs, or secrets, could be negative, and this makes the comparison still undeterministic at this point. Thus, it may be good to make sure only positive k's or p's are considered at this point.
#13: generate a public value to create this behavior.

#of course we might as well just try different relations between s, s', and k directly without forming k ourselves... but that brings us a lot less close to a solution if we don't know what exactly the relation is in the actual program. current approach should give us more fine-grained control. A problem with a guessing approach is also that if you don't know that there is a s>=k relationship, you don't know whether s==k+1 and s'==k are actually edge cases

"""
how do we deal with multiple relations on s? should we treat them individually or holistically?
let's not worry about this right now
ultimately it's of course about holistic relationships...
if we have rel1 and rel2 both together may determine different timing behavior... whereas individually they don't at all, so we may need to look at combinations. of course looking at all combinations quickly becomes complex.

        rel1  rel2
        ----------
      T| t1    t2
      F| t2    t1
"""

#it's probably good right now to add support to warn about different policy violations.
#add a violation manager in the analysis framework which maintains a binaries violation and for each violation add a type, location, and violating paths
#however, we cannot use self-composition to identify violations after every instruction, this would slow the program down significantly. So should probably add a secret-tracking taint analysis technique so atleast we don't have to use self composition when secrets aren't used as inputs. self-composition may then be a nice technique to verify dependence
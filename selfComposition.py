from __future__ import print_function
import sys
import claripy
import re

totalpart1 = 0

class SelfComposition(claripy.Solver):
    """
    A class to replace a state's solver from the beginning of symbolic execution. It will modify constraint logging for more efficient self-composition analysis. Don't forget to specify the self-composition connectors from the beginning. They can be added later but this is a lot more inefficient.
    
    TODO PARKED: should we implement a "temporary connector" so we can work with dependencies?
            Because we don't always want to perform the selfcomposition proof over time
        -> for now, just work with branches. the time connector is also only added in the end.
    """
    def __init__(self, composeCount=2):
        claripy.Solver.__init__(self)
        self.composeCount = composeCount
        # symbolTranslation[symbolName][i] = BVS(symbolCopy_i)
        self.symbolTranslation = {}     # a dictionary from main symbol names to a list of copies of that symbol. The first symbol "copy" to use should always be the symbol itself, this isn't maintained in the list.
        self.translationDict = []       # a list of dictionaries for each composition copy, containing main symbol cache keys to copy symbols.
        for c in range(0,self.composeCount-1):
            self.translationDict.append({})
        self.reverseSymbolTranslation = {} # a reverse lookup table to go from symbol copy names to main symbols. Includes references for the main symbol name itself.
        self.inequalities = []          # inequality connectors (equality connectors aren't actually processed)
        self.inequalSymbols = set([])   # the set of symbol names in the inequality set
        self.compositionCopyConstraints = [] # list of constraint copies used for self-composition
        
    def symbols(self):
        """Returns a list of symbol names used in this solvers main constraints; use sparingly"""
        symbols = set([])
        for c in self.constraints:
            symbols = symbols.union(c.variables)
        return symbols
        
        
    def __copy(self, other):
        other.composeCount = self.composeCount
        for symbolName in (self.symbolTranslation):
            other.symbolTranslation[symbolName] = []
            other.symbolTranslation[symbolName].extend(self.symbolTranslation[symbolName])
        for k,dict in enumerate(self.translationDict):
            for t in dict:
                other.translationDict[k][t] = dict[t]
        for t in self.reverseSymbolTranslation:
            other.reverseSymbolTranslation[t] = self.reverseSymbolTranslation[t]
        other.inequalities.extend(self.inequalities)
        other.inequalSymbols = other.inequalSymbols.union(self.inequalSymbols)
        other.compositionCopyConstraints.extend(self.compositionCopyConstraints)
        
    def blank_copy(self):
        return SelfComposition(self.composeCount)
        
    def branch(self):
        superbranch = claripy.Solver.branch(self)
        self.__copy(superbranch)
        return superbranch
        
    def symbolCopies(self, symbol, n=None):
        """
        Provides access to n versions of a symbol to model #n-self-composition.
        Current implementation can only process BVS type symbols
        
        Note: any copied symbol is added to the symbolTranslation and translationDict maps.
        """
        if n == None:
            n = self.composeCount
        key = symbol.args[0]    #key is the symbol name
        if key not in self.symbolTranslation:
            self.symbolTranslation[key] = []
            self.reverseSymbolTranslation[key] = symbol
        if len(self.symbolTranslation[key]) < n-1:
            rangeStart = len(self.symbolTranslation[key]) if key in self.symbolTranslation else 0 #allows for incrementing of translation set after initial analysis
            for i in range(rangeStart, n-1):
                if isinstance(symbol, claripy.ast.bv.BV):
                    symbolCopy = claripy.BVS("%s_copy(%d)" % (symbol.args[0],i), symbol.length)
                    self.symbolTranslation[key].append(symbolCopy)
                    self.reverseSymbolTranslation[symbolCopy.args[0]] = symbol
                    self.translationDict[i][symbol.cache_key] = symbolCopy
        
        result = [symbol]         
        result.extend(self.symbolTranslation[key])
        return result
        
    def addInequalityConnector(self, symbol):
        """Adds an inequality connector over the provided symbol; quick way of calling c=symbolCopies(symbol,2); addConnector(c[0] != c[1])"""
        if len(symbol.variables) == 1:
            c = self.symbolCopies(symbol)
            c0 = c[0]
            c1 = c[1]
        else:
            for s in symbol.recursive_leaf_asts:
                if s.symbolic:
                    self.symbolCopies(s)
            c0 = symbol
            c1 = symbol.replace_dict(self.translationDict[0])
        self.addConnector(c0 != c1)
        
    def addConnector(self, connector):
        """Adds connection between composed constraint sets. The connector is an AST which expresses a certain inequality between symbol copies. Use symbolCopies(S) to access the copies. This function expects simple expressions of the form (symbolcopy0 _operation_ symbolcopy1), we don't guarantee it works for more complex expressions
        
        TODO low priority: allow for connectors to be added in hindsight and  upgrade current constraint set to copies if necessary
        """
        self.inequalities.append(connector)
        connectorSymbolsUnprocessed = set(connector.variables)
        
        itemsToRemove = set([])
        
        for symbol in connectorSymbolsUnprocessed: #first identify all symbols which are copies and add their main symbol to the set of inequalsymbols
            if symbol in self.reverseSymbolTranslation:
                self.inequalSymbols.add(self.reverseSymbolTranslation[symbol].args[0])
                itemsToRemove.add(symbol)
        if len(itemsToRemove) < len(connectorSymbolsUnprocessed): #if there are any leftover symbols, they must be main symbols, so add them directly.
            for symbol in connectorSymbolsUnprocessed.difference(itemsToRemove):
                self.inequalSymbols.add(self.reverseSymbolTranslation[symbol].args[0])
        
    def addAuxiliaries(self, constraintList, **kwargs):
        """This function allows one to add auxiliary constraints which aren't processed like other constraints. In the first place it is intended to add constraints for post-processing of constraint sets"""
        result = claripy.Solver.add(self, constraintList, **kwargs) #perform the main constraint add
        return result
        
    def add(self, constraintList, **kwargs):
        """The normal Solver add functionality, but does some extra processing to prepare for self-composition analysis. Returns the result of the main, unprocessed, constraint add.
        constraintList is either a single constraint or a list of constraints"""
        #first, check whether which symbols in the constraint are in the inequality list
        
        if type(constraintList) not in [list, tuple]:
            constraintList = [constraintList]
        elif type(constraintList) == tuple:
            constraintList = list(constraintList)
        
        #simplify constraints which are added, and check if the constraint isn't trivial (having trivial constraint in the constraint list slows down execution by about 10%)
        i = len(constraintList)-1
        while True:
            simplified = claripy.backends.z3.simplify(constraintList[i])
            if simplified.cache_key == claripy.true.cache_key:
                del constraintList[i]
            else:
                constraintList[i] = simplified
            if i == 0:
                break
            else:
                i -= 1
                
        for constraint in constraintList:
            containsCompositionSymbols = False
            for symbolName in constraint.variables:
                if symbolName in self.inequalSymbols:
                    containsCompositionSymbols = True
                    break
            if containsCompositionSymbols: #if there are inequalities, replace 
                for k in range(0,self.composeCount-1):
                    copy = constraint.replace_dict(self.translationDict[k])
                    self.compositionCopyConstraints.append(copy)
        
        result = claripy.Solver.add(self, constraintList, **kwargs) #perform the main constraint add
            
        return result
        
    def compositionEval(self, e, n, extra_constraints = [], exact=None):
        compositionConstraints = []
        compositionConstraints.extend(self.inequalities)
        compositionConstraints.extend(self.compositionCopyConstraints)
        compositionConstraints.extend(extra_constraints)
        return claripy.Solver.eval(self, e, n, extra_constraints=tuple(compositionConstraints), exact=exact)
        
    def compositionSatisfiable(self, extra_constraints = [], **kwargs):
        """Attempts to proof whether the self-composition is satisfiable"""
        compositionConstraints = []
        compositionConstraints.extend(self.inequalities)
        compositionConstraints.extend(self.compositionCopyConstraints)
        compositionConstraints.extend(extra_constraints)
        return claripy.Solver.satisfiable(self, compositionConstraints, **kwargs)
        
    def proofInequalityPossible(self, expression, proofComponents=True, extraConstrainedSymbolNames=[]):
        """
            proofs an inequality over copies of the expression to be possible in the self-composition
            if proofComponents is True(default), then first all symbols in the expression are checked for inequality. If no constrained symbol is proven unequal, the result is false. If any is true, the entire expression is checked.
        """
        
        if proofComponents:
            if not self._proofComponents(expression, extraConstrainedSymbolNames):
                #print("component analyses proved inequality not possible")
                return False
            #else:
            #    print("component analysis inconclusive, continuing analysis")
            
        solver = self.branch()
        t = claripy.BVS("t", expression.length)
        solver.addInequalityConnector(t)
        solver.add(t == expression)
        result = solver.compositionSatisfiable()
        return result
        
    def _proofComponents(self, expression, extraConstrainedSymbolNames=[]):
        """
            returns true if any of the components in expression can be proven inequal in the self-composition
            however, it doesn't look at symbols which aren't constrained in this state, unless they are supplied as extraConstrainedSymbolNames
            extraConstrainedSymbolNames is a list of symbol names which are also considered constrained
        """
        componentsToProve = set([])
        constrainedVars = set(extraConstrainedSymbolNames)
        for c in self.constraints:
            constrainedVars = constrainedVars.union(c.variables)
        constrainedVars = constrainedVars.union(self.inequalSymbols)
        for l in expression.recursive_leaf_asts:
            if len(l.variables)>0 and l.args[0] in constrainedVars:
                componentsToProve.add(l)
                constrainedVars.remove(l.args[0])
                if len(constrainedVars) == 0:
                    break
        for c in componentsToProve:
            if self.proofInequalityPossible(c, proofComponents=False):
                return True
        return False
        
    def dynamicRange(solver, symbol):
        """
        returns two symbol values with the maximum absolute difference between them.
        """
        symCopies = solver.symbolCopies(symbol)
        print("computing dynamic range...", end='')
        sys.stdout.flush()
        solverCopy = solver.branch()
        solverCopy.addConnector((symCopies[1] - symCopies[0]).SGT(0))
        maxRange = solverCopy.max(symCopies[1] - symCopies[0], useComposition=True)
        solverCopy.addConnector((symCopies[1] - symCopies[0]) == maxRange)
        tlow = solverCopy.min(symCopies[0], useComposition=True)
        thigh = tlow + maxRange
        print("\r", end='')
        sys.stdout.flush()
        return (tlow, thigh)
        
    def dynamicRatio(solver, symbol):
        """
        returns two symbol values with the maximum rational difference between them.
        """
        symCopies = solver.symbolCopies(symbol)
        print("computing dynamic ratio...", end='')
        sys.stdout.flush()
        solverCopy = solver.branch()
        #the factor 1000 prevents integer rounding problems
        solverCopy.addConnector((symCopies[1]*1000 / symCopies[0]).SGT(0))
        maxRange = solverCopy.max(symCopies[1]*1000 / symCopies[0], useComposition=True)
        solverCopy.addConnector((symCopies[1]*1000 / symCopies[0]) == maxRange)
        tlow = solverCopy.min(symCopies[0], useComposition=True)
        thigh = solverCopy.max(symCopies[1], useComposition=True)
        print("\r                                 \r", end='')
        sys.stdout.flush()
        return (tlow, thigh)
        
    def _checkCompositionParamaters(self, useComposition, e, **kwargs):
        if useComposition == None and type(e) == claripy.ast.bv.BV:
            for symbolName in e.variables:
                if symbolName in self.reverseSymbolTranslation and symbolName not in self.inequalSymbols: #this validates whether the symbols is a copied symbol
                    useComposition = True
                    break
        if useComposition == True: #if the expression contains symbols from a composition copy, perform the function over the self-composition
            compositionConstraints = []
            compositionConstraints.extend(self.inequalities)
            compositionConstraints.extend(self.compositionCopyConstraints)
            if 'extra_constraints' in kwargs:
                compositionConstraints.extend(kwargs['extra_constraints'])
            kwargs['extra_constraints'] = compositionConstraints
        return (e, kwargs)
        
    def max(self, e, useComposition=None, **kwargs):
        (e, kwargs) = self._checkCompositionParamaters(useComposition, e, **kwargs)
        return claripy.Solver.max(self, e, **kwargs)
        
    def min(self, e, useComposition=None, **kwargs):
        (e, kwargs) = self._checkCompositionParamaters(useComposition, e, **kwargs)
        return claripy.Solver.min(self, e, **kwargs)
        
    def eval(self, e, n, useComposition=None, **kwargs):
        (e, kwargs) = self._checkCompositionParamaters(useComposition, e, **kwargs)
        return claripy.Solver.eval(self, e, n, **kwargs)
        
    def is_false(self, e, useComposition=None, **kwargs):
        (e, kwargs) = self._checkCompositionParamaters(useComposition, e, **kwargs)
        return claripy.Solver.is_false(self, e, **kwargs)
        
    def is_true(self, e, useComposition=None, **kwargs):
        (e, kwargs) = self._checkCompositionParamaters(useComposition, e, **kwargs)
        return claripy.Solver.is_true(self, e, **kwargs)
        
    def solution(self, e, v, useComposition=None, **kwargs):
        (e, kwargs) = self._checkCompositionParamaters(useComposition, e, **kwargs)
        return claripy.Solver.solution(self, e, v, **kwargs)
        
    def hasMultipleSolutions(self, expression, extraConstraints = []):
        if not self.satisfiable(extraConstraints):
            return False
        else:
            one_solution = self.eval(expression,1, extraConstraints=extraConstraints)
            if len(one_solution) == 0:
                return False
            else:
                extras = [expression != one_solution[0]]
                extras.extend(extraConstraints)
                return self.satisfiable(extras)
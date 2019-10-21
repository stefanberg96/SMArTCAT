import pyvex

class Time(pyvex.stmt.IRStmt):
    """
    An expression to keep track of execution time
    """

    __slots__ = ['instruction', 'dependsOn', 'keyStatement', 'instructionAddress']

    class surrogate_c_stmt(object):
        def __init__(self):
            self.tag = 0

    def __init__(self, irsb, instruction, keyStatement, instructionAddress):
        c_stmt = self.surrogate_c_stmt()
        pyvex.stmt.IRStmt.__init__(self, c_stmt, irsb)
        self.arch = irsb.arch
        self.tag = 'Ist_Time'
        self.instruction = instruction
        self.dependsOn = 4 #listOfRegisters/Temps/constants/simExpressions?
        self.keyStatement = keyStatement
        self.instructionAddress = instructionAddress

    def __str__(self):
        return "+++++ Timing (%s) +++++" % (self.instruction)

    @staticmethod
    #maybe we can circumvent the tag hack with the surrogate statement by not relying on the tagtoclass function but instead just using the TimedSimIRSB constructor
    def _translate(c_stmt, irsb):
        if c_stmt[0] == ffi.NULL:
            return None

        tag = c_stmt.tag
        try:
            stmt_class = _tag_to_class[tag]
        except KeyError:
            raise PyVEXError('Unknown/unsupported IRStmtTag %s\n' % ints_to_enums[tag])
        return stmt_class(c_stmt, irsb)
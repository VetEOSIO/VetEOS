from veteos.octopus.arch.wasm.instruction import WasmInstruction


# for instruction initialization (WIP)
class VetInstruction(WasmInstruction):
    """
    VetEOS Instruction
    """

    def __init__(self, opcode, name, imm_struct, operand_size, insn_byte,
                 pops, pushes, description, operand_interpretation=None, offset=0):
        super().__init__(opcode, name, imm_struct, operand_size, insn_byte,
                         pops, pushes, description, operand_interpretation, offset)
        self.dataflow = None

    @property
    def is_eq(self):
        return '.eq' in self.name

    @property
    def is_ne(self):
        return '.ne' in self.name and 'neg' not in self.name and 'nea' not in self.name

    @property
    def is_lt(self):
        return '.lt' in self.name

    @property
    def is_gt(self):
        return '.gt' in self.name

    @property
    def is_le(self):
        return '.le' in self.name

    @property
    def is_ge(self):
        return '.ge' in self.name and 'get' not in self.name

    @property
    def is_cmp_ins(self):
        return self.is_eq or self.is_ne or self.is_lt or self.is_gt or self.is_le or self.is_ge

    @property
    def is_load_ins(self):
        return 'load' in self.name

    @property
    def is_store_ins(self):
        return 'store' in self.name

    @property
    def is_call_ins(self):
        return 'call' in self.name

    @property
    def is_constant_ins(self):
        return 'const' in self.name

    @property
    def is_get_local_ins(self):
        return 'get_local' in self.name

    def get_ins_interpretation(self) -> str:
        '''
        return the operand_interpretation of an Instruction
        '''
        return self.operand_interpretation if self.operand_interpretation != None else self.name

    def get_local_global_name(self) -> str:
        '''
        return the local/global variable name, e.g. "local 0"
        '''
        return self.operand_interpretation.split('_')[-1]

    def set_dataflow(self, data: str):
        '''
        add dataflow information as strings
        '''
        self.dataflow = ' [%s]' % data

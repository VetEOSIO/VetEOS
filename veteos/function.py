from veteos.octopus.arch.wasm.cfg import Function
from veteos.instruction import VetInstruction
from veteos.node import Node
from veteos.utils import *


class VetFunction(Function):
    '''
    VetEOS Function, for function initialization (WIP)
    '''

    def __init__(self, name: str, func: Function, return_values) -> None:
        self.name = name
        self.func = func
        self.return_values = return_values
        self.BNet = {}
        self.basicblocks = []
        self.instructions = []
        self.instruction_dic = {}
        self.instr_to_block = {}
        self.param = None
        self.param_num = None
        self.param_size = None
        self.stack_size = None

    def analyze(self):
        # self.return_values = self.emul.emul.return_values
        for i in self.func.instructions:
            self.instructions[i.offset] = i
            if i.name == 'return':
                if i.ssa.args:
                    for a in i.ssa.args:
                        addi(a, self.return_values)
        for b in self.func.basicblocks:
            # TODO: the block_name adding zeros, error occur
            # key = self.block_name(b.name)
            key = b.name
            if key not in self.BNet.keys():
                self.BNet[key] = Node(b)
                # print(key)
        edges = self.get_edges()
        for e in edges:
            # print(e)
            # TODO: the block_name adding zeros, error occur
            # parent = self.block_name(e.node_from)
            # child = self.block_name(e.node_to)
            parent = e.node_from
            child = e.node_to
            addi(child, self.BNet[parent].children)
            addi(parent, self.BNet[child].parents)

        for k in sorted(self.BNet.keys()):
            # print(k+':'+str(self.BNet[k]))
            self.basicblocks.append(self.BNet[k].data)
            for i in self.BNet[k].data.instructions:
                self.instr_to_block[i.offset] = self.BNet[k].data.name

    def get_edges(self):
        functions_block = self.func.basicblocks
        block_name = [b.name for block_l in functions_block for b in block_l]
        edges = [edge for edge in edges if (
            edge.node_from in block_name or edge.node_to in block_name)]
        return edges

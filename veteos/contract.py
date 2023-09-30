from veteos.octopus.arch.wasm.emulator import WasmSSAEmulatorEngine
from veteos.function import VetFunction
from veteos.core import Func
from veteos.utils import *


class Contract:
    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.emul = self.init_emul(filename)
        self.funcs = {}
        self.actions = []
        self.edges_from = {}
        self.edges_to = {}

    def init_emul(self, filename: str) -> WasmSSAEmulatorEngine:
        fp = open(filename, 'rb')
        octo_bytecode = fp.read()
        emul = WasmSSAEmulatorEngine(octo_bytecode)
        fp.close()
        return emul

    def analyze(self, func_name: list):
        if len(func_name) > 0:
            self.emul.emulate_functions(func_name)
        # try to emulate main by default
        else:
            self.emul.emulate_functions()

    def show_cfg(self, func_name: list):
        from veteos.octopus.analysis.graph import CFGGraph
        ssa_cfg = CFGGraph(self.emul.cfg)
        if func_name != None and len(func_name) > 0:
            ssa_cfg.view_functions(only_func_name=func_name,
                                   simplify=False,
                                   ssa=True)
        else:
            ssa_cfg.view(simplify=False, ssa=True)

    def show_call_graph(self):
        from veteos.octopus.arch.wasm.cfg import WasmCFG
        fp = open(self.filename, 'rb')
        octo_bytecode = fp.read()
        octo_cfg = WasmCFG(octo_bytecode)
        fp.close()
        octo_cfg.visualize_call_flow()
        return

    def init_edges(self):
        '''
        initialize the edges
        '''
        if len(self.edges_from) > 0:
            return
        nodes, edges = self.emul.cfg.get_functions_call_edges()
        for e in edges:
            fr = e.node_from
            to = e.node_to
            if fr not in self.edges_from.keys():
                self.edges_from[fr] = []
            if to not in self.edges_to.keys():
                self.edges_to[to] = []
            self.edges_from[fr].append(to)
            self.edges_to[to].append(fr)

    def get_call_edges_from(self, func_name: str, full: bool = False) -> list:
        '''
        get the edges started from a function
        '''
        '''
        return all the callee functions of a funtion
        - return a list of str
        - no duplicated names when full == False
        '''
        if len(self.edges_from) == 0:
            self.init_edges()
        if func_name in self.edges_from.keys():
            edges = self.edges_from[func_name]
            if not full:
                return list(set(edges))
            else:
                return edges
        return None

    def get_call_edges_to(self, func_name: str, full: bool = False) -> list:
        '''
        get the edges connected to a function, return None if N/A

        return all the caller functions of a funtion
        - return a list of str
        - no duplicated names when full == False
        '''
        if len(self.edges_to) == 0:
            self.init_edges()
        if func_name in self.edges_to.keys():
            edges = self.edges_to[func_name]
            if not full:
                return list(set(edges))
            else:
                return edges
        return None

    def get_edges(self, func_name: list) -> list:
        '''
        return the edges in specific functions
        func_name: a list of function names
        '''
        functions = self.emul.cfg.functions
        edges = self.emul.cfg.edges     # all edges in graph

        if len(func_name) > 0:
            functions = [
                func for func in self.emul.cfg.functions if func.name in func_name]
            functions_block = [func.basicblocks for func in functions]
            block_name = [
                b.name for block_l in functions_block for b in block_l]
            edges = [edge for edge in edges if (
                edge.node_from in block_name or edge.node_to in block_name)]
        return edges

    def get_import_len(self) -> int:
        '''
        return the number of import functions
        '''
        return len(self.emul.ana.imports_func)

    def get_function(self, name: str) -> Function:
        '''
        reutrn a octopus.function object, return None if not found
        '''
        # return self.emul.cfg.get_function(name)
        for f in self.emul.cfg.functions:
            if f.name == name:
                return f
        return None

    def get_Func(self, name: str):
        '''
        return a Func object useing name
        '''
        if name not in self.funcs.keys():
            # here should be the only place to init Func
            self.funcs[name] = Func(self, name)
        return self.funcs[name]

    def get_VetFunction(self, name: str):
        '''
        return a VetFunction object, return None if not found the name
        '''
        if name not in self.funcs.keys():
            func = self.get_function(name)
            if func == None:
                return None
            self.funcs[name] = VetFunction(name, func)
        return self.funcs[name]

    def get_func_name(self, index: int) -> str:
        '''
        retrun the function name using the index
        '''
        try:
            return self.emul.ana.func_prototypes[int(index)][0]
        except:
            return None

    def check_func_name(self, name: str):
        '''
        check whther the function is in the contract
        '''
        for f in self.emul.ana.func_prototypes:
            if name in f[0]:
                return f[0]
        return None

    def get_func_prototype(self, name: str):
        '''
        retrun the function prototype using the name
        '''
        for p in self.emul.ana.func_prototypes:
            if p[0] == name:
                return p
        return None

    def get_all_function_names(self) -> list:
        '''
        return a list containing all function names
        '''
        return [f.name for f in self.emul.cfg.functions]

    def get_actions(self) -> list:
        '''
        return a list containing the action names of a contract
        '''
        # TODO: why self.actions will be None?
        if self.actions != None and len(self.actions) == 0:
            self.init_edges()
            self.actions = self.get_call_edges_to('read_action_data')
            # self.actions = list(set(self.get_call_edges_to(
            #     'read_action_data')+self.get_call_edges_to('action_data_size')))
            # res=[]
            # for k in self.edges_from.keys():
            #     if 'read_action_data' in self.get_call_edges_from(k) or \
            #             'action_data_size' in self.get_call_edges_from(k):
            #         res.append(k)
            # self.actions = res
        return self.actions if self.actions != None else []

    def get_action_strings_from_apply(self) -> list:
        '''
        search for the strings in apply, return the action names
        '''
        apply = self.get_function('apply')
        res = []
        if apply is None:
            return res
        instrs = apply.instructions
        for i, ins in enumerate(instrs):
            if is_cmp_ins(ins.name) and i > 1:
                idx = -1
                if 'i64.const' in instrs[i-1].name and 'local 2' in get_ins_interpretation(instrs[i-2]):
                    idx = i-1
                elif 'i64.const' in instrs[i-2].name and 'local 2' in get_ins_interpretation(instrs[i-1]):
                    idx = i-2
                if idx != -1:
                    name = get_ins_interpretation(instrs[idx]).split()[-1]
                    res.append([idx, name, eosio_name_decoder(int(name))])
        return res

    def get_strings_from_function(self, name: str) -> list:
        '''
        search for all strings in a function
        '''
        func = self.get_function(name)
        res = []
        for ins in func.instructions:
            if 'i64.const' in ins.name:
                s = eosio_name_decoder(
                    int(get_ins_interpretation(ins).split()[-1]))
                if len(s) > 0:
                    res.append(s)
        return res

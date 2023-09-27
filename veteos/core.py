from octopus.arch.wasm.emulator import WasmSSAEmulatorEngine as WE


from veteos.utils import *
import timeout_decorator


class Contract:
    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.emul = self.init_emul(filename)
        self.funcs = {}
        self.actions = []
        self.edges_from = {}
        self.edges_to = {}

    def init_emul(self, filename: str) -> WE:
        fp = open(filename, 'rb')
        octo_bytecode = fp.read()
        emul = WE(octo_bytecode)
        fp.close()
        return emul

    def analyze(self, func_name: list):
        if len(func_name) > 0:
            self.emul.emulate_functions(func_name)
        # try to emulate main by default
        else:
            self.emul.emulate_functions()

    def show_cfg(self, func_name: list):
        from octopus.analysis.graph import CFGGraph
        ssa_cfg = CFGGraph(self.emul.cfg)
        if func_name != None and len(func_name) > 0:
            ssa_cfg.view_functions(only_func_name=func_name,
                                   simplify=False,
                                   ssa=True)
        else:
            ssa_cfg.view(simplify=False, ssa=True)

    def show_call_graph(self):
        from octopus.arch.wasm.cfg import WasmCFG
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


class Func():
    def __init__(self, emul: Contract, name: str) -> None:
        self.name = name
        self.emul = emul
        self.func = None
        self.BNet = {}
        self.basicblocks = []
        self.instructions = {}
        self.instr_to_block = {}
        self.return_values = []
        self.param = None
        self.param_num = None
        self.param_size = None
        self.stack_size = None

        self.emul.analyze([name])
        for f in self.emul.emul.cfg.functions:
            if f.name == name:
                self.func = f
                break
        if self.func:
            self.analyze()
        else:
            print('function name not found')

    def analyze(self):
        self.return_values = self.emul.emul.return_values
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
        edges = self.emul.get_edges([self.name])
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

    def block_name(self, name: str) -> str:
        '''
        adding zeros before the block number
        '''
        max_ins = len('%x' % (self.func.instructions[-1].offset))
        si = name.rfind('_')+1
        bn = name[si:]
        bn = '0'*(max_ins-len(bn))+bn
        return name[:si]+bn

    def print_net(self):
        for k in sorted(self.BNet.keys()):
            print(k+':'+str(self.BNet[k]))

    def get_memo_instr(self) -> list:
        memo_ins = []
        for i in self.func.instructions:
            if is_load_ins(i) or is_store_ins(i):
                addi(i, memo_ins)
        return memo_ins

    def init_param(self):
        if self.param == None:
            fn = self.func.prefered_name
            self.param = fn[fn.index('(')+1:fn.index(')')].split()
            self.param_num = len(self.param)
            param_size = []
            for pa in self.param:
                if '32' in pa:
                    param_size.append(4)
                elif '64' in pa:
                    param_size.append(8)
            self.param_size = param_size

    def get_param(self) -> list:
        '''
        return the parameters
        '''
        if self.param == None:
            self.init_param()
        return self.param

    def get_param_num(self) -> int:
        '''
        return the parameters
        '''
        if self.param_num == None:
            self.init_param()
        return self.param_num

    def get_param_size(self) -> list:
        '''
        return the parameters
        '''
        if self.param_size == None:
            self.init_param()
        return self.param_size

    def get_stack_size(self) -> int:
        '''
        return the size of function stack
        '''
        if self.stack_size == None:
            instrs = self.func.instructions
            for idx, ins in enumerate(instrs):
                if 'get_global' in ins.name and idx+2 < len(instrs):
                    if 'i32.const' in instrs[idx+1].name \
                            and 'i32.sub' in instrs[idx+2].name:
                        res = instrs[idx+1].operand_interpretation.split()[1]
                        self.stack_size = int(res)
                        return self.stack_size
            self.stack_size = -1  # cannot determine
        return self.stack_size

    def is_parameter(self, instr: Instruction) -> bool:
        '''
        determine if an instruction is reading parameters
        '''
        if 'get_local' in instr.name:
            pn = self.get_param_num()
            para_index = instr.operand_interpretation.split()[1]
            # if int(para_index) < pn-1:
            if int(para_index) < pn:
                return True
        elif 'load' in instr.name:
            stack_size = self.get_stack_size()
            offset = int(instr.operand_interpretation.split()[-1])
            param_size = sum(self.get_param_size())
            if offset >= stack_size-param_size:
                return True
        return False

    def set_local_ssa(self, num: str):
        n = str(num)
        local = 'local '+n
        localssa = local_ssa(local, self.BNet)
        for i in localssa:
            set_dataflow(i.data, str(i))
        return


class Node():
    def __init__(self, data) -> None:
        self.data = data
        self.parents = []
        self.children = []

    def __str__(self):
        return str(self.as_dict())

    def as_dict(self):
        return {  # 'data': str(self.data),
            'parents': str(self.parents),
            'children': str(self.children)}


@timeout_decorator.timeout(5)
def get_func_wrapper(emul: Contract, fn: str):
    try:
        func = emul.get_Func(fn)
    except:
        raise TimeoutError("get func timeout: "+fn)
    return func


@timeout_decorator.timeout(5)
def get_emul_wrapper(file: str):
    try:
        return Contract(file)
    except:
        raise TimeoutError("init Emul timeout")


class LocalSSA():
    def __init__(self, data: Instruction, asmt: str, args: str) -> None:
        self.data = data
        self.asmt = asmt
        self.args = args

    def __str__(self) -> str:
        return ' = '.join([self.asmt, self.args])


def local_ssa(local: str, BNet: dict):
    local_idx = 0
    block_idx = {}
    res = []
    for k in sorted(BNet.keys()):
        b = BNet[k].data
        for i in b.instructions:
            if i.operand_interpretation and local in i.operand_interpretation:
                # print(i.ssa.format())
                block = k
                if 'set' in i.name or 'tee' in i.name:
                    asmt = i.ssa.method_name.split(
                        '_')[-1].replace(' ', '')+'_'+str(local_idx)
                    block_idx[block] = {'ssa': asmt, 'offset': i.offset}
                    args = ''
                    if i.ssa.args is not None:
                        args += ', '.join('%{:02X}'.format(arg.ssa.new_assignement)
                                          for arg in i.ssa.args)
                    # out=' = '.join([asmt,args])
                    # res.append(out)
                    res.append(LocalSSA(i, asmt, args))
                    local_idx += 1
                elif 'get' in i.name:
                    args = merge_local_ssa(block, BNet, block_idx, [])
                    if args == '':  # there is no assignment to this local before
                        args = local.replace(' ', '')+'(undefined)'
                    asmt = ''
                    if i.ssa.new_assignement is not None:
                        asmt += '%{:02X}'.format(i.ssa.new_assignement)
                    # out=' = '.join([asmt,args])
                    # res.append(out)
                    res.append(LocalSSA(i, asmt, args))
    # printl(res)
    return res


def merge_local_ssa(block: str, Bnet: dict, block_idx: dict, visited: list):
    if block in block_idx.keys():
        return block_idx[block]['ssa']
    else:
        addi(block, visited)   # mark block as visited
        res = []
        parents = Bnet[block].parents
        if len(parents) == 0:   # no source of local
            return ''
        for p in parents:
            if p in visited:  # avoid loop
                continue
            mer = merge_local_ssa(p, Bnet, block_idx, visited)
            if len(mer) > 0:
                addi(mer, res)
        ssa = ''
        if len(res) > 1:
            ssa += 'Final('+', '.join(res)+')'
        elif len(res) == 1:
            ssa += res[0]
        block_idx[block] = {'ssa': ssa, 'offset': -1}
        return ssa


def memory_ssa(memo: str, BNet: dict, ins2blk: dict, memo_ins: list):
    memo_l = []
    for i in memo_ins:
        if memo in str(i):
            memo_l.append(i)
    local_idx = 0
    block_idx = {}
    res = []
    for m in memo_l:
        i = m.data
        block = ins2blk[i.offset]
        if 'store' in i.name:
            asmt = m.asmt.replace(' ', '')+'_'+str(local_idx)
            block_idx[block] = {'ssa': asmt, 'offset': i.offset}
            res.append(LocalSSA(i, asmt, m.args))
            local_idx += 1
        if 'load' in i.name:
            args = merge_local_ssa(block, BNet, block_idx, [])
            if len(args) == 0:
                args = m.args.replace(' ', '')
            res.append(LocalSSA(i, m.asmt, args))
    # printl(res)
    return res


def get_memory_ssa(memo_instr: list, locals: list, func: Func) -> list:
    '''
    translate 'load' and 'store' instructions: \n
    convert their arguments to 'local(base address) + offset' \n
    parameters:
    - memo_instr: a list containing memory instructions
    - locals: the name of locals related to the memo_instr
    - func: an Func object containing memo_instr
    '''
    # TODO: this function based on an unroubust assumption:
    # the args of load & store are directly linked to the results of local.get
    localssa = []
    # get ssa for all locals
    for local in locals:
        localssa += local_ssa(local, func.BNet)
    # convert locals to specific variable names (tanslate load and store)
    res = []
    for i in memo_instr:
        # get the source ins of memo, which is a local.get (or global.get)
        pre_ins = track_prev_all(i.ssa.args[-1], func)  # second para
        local_ins = None
        for p in pre_ins:
            if 'get' in p.name:
                local_ins = p
                break
        local0 = get_ins_ssa(local_ins, localssa)
        istr = i.ssa.format()
        '''print(istr)
        print(local_ins.ssa.format())
        print(local0)
        print(locals)'''
        # print(i.operand)
        ll = istr.find(',')
        rr = istr.find('(')
        # print(ll, rr)
        offset = istr[ll+2:rr]
        if is_load_ins(i):
            asmt, _ = istr.split(' = ')
            args = local0+' + '+offset
        elif is_store_ins(i):
            args = istr[rr+1:istr.rfind(',')]
            asmt = local0+' + '+offset
        res.append(LocalSSA(i, asmt, args))

    return res


def track_prev(instr: Instruction):
    '''if instr.ssa.is_constant:
        return []'''
    ins = [instr]
    if not instr.ssa.is_constant and instr.ssa.args is not None:
        for arg in instr.ssa.args:
            ins += track_prev(arg)
    return ins


def track_prev_with_local(instr: Instruction, func: Func):
    # 1st step
    pre_ins = track_prev(instr)
    locals = []
    local_ins = []
    new_ins = []
    for p in pre_ins:
        if 'local' in p.name:
            addi(get_local_global_name(p), locals)
            local_ins.append(p)
    for local in locals:    # for each local
        localssa = local_ssa(local, func.BNet)
        # printl(localssa)
        for l in local_ins:  # find the ins using local
            local0 = None
            for s in localssa:
                if l == s.data:  # must be get_local
                    local0 = s.args
                    # print(s)
                    break
            if local0 is None:
                # cannot find the local (should not happen)
                print('error', local)
                continue
            for s in localssa:
                if s.asmt == local0:  # add the get_local to ins
                    addi(s.data, new_ins)
    res = []+pre_ins
    for i in new_ins:
        res += track_prev(i)
    '''for i in res:
        print(i.ssa.format())'''
    # TODO: second (multiple) level of locals
    # exit(0)
    return res


def get_ins_ssa(instr: Instruction, ssalist: list) -> str:
    '''
    return the ssa form of the argument of instruction\n
    parameters:
    - instr: the instruction whose argument is local or memo or global 
    (usually a 'get' or 'load' instr)
    - ssalist: a list containing all ssa of the target variable
    '''
    for s in ssalist:
        if instr == s.data:
            return s.args


def get_local_source(instr: Instruction, func: Func):
    '''
    return the data source of a local, i.e. return a local.set instruction\n
    parameters:
    - instr: the instruction using a local, i.e. a local.get instruction
    - func: the function containing the instr
    '''
    local = get_local_global_name(instr)
    localssa = local_ssa(local, func.BNet)
    # the local in ssa format (with ssa index)
    local0 = get_ins_ssa(instr, localssa)
    if local0 is None:    # cannot find the local (should not happen)
        return None
    for s in localssa:
        if s.asmt == local0:    # found the source
            return s.data
    return None  # source not found


def get_memo_source(instr: Instruction, func: Func):
    '''
    return the data source of a memory slot, i.e. return a store instruction\n
    parameters:
    - instr: the instruction loading from memory
    - func: the function containing the instr
    '''
    # TODO: currently only analyze in one single function
    memo_instr = func.get_memo_instr()   # find memory instructions
    locals = get_locals(memo_instr)     # find memory-related locals
    memo_ssa = get_memory_ssa(memo_instr, locals, func)
    # the memo in ssa format (with ssa index)
    memo0 = get_ins_ssa(instr, memo_ssa)
    if memo0 is None:    # cannot find the ins (should not happen)
        return None
    for s in memo_ssa:
        if s.asmt == memo0:    # found the source
            return s.data
    return None  # source not found


def get_prev_source(prev_ins: list) -> Instruction:
    '''
    return the source instruction from a sequence of instructions
    '''
    return prev_ins[-1]


def track_prev_one(instr: Instruction):
    if is_constant_ins(instr):
        return None
    '''if is_call_ins(instr):
        return None'''
    if instr.ssa.args:
        return instr.ssa.args
    return None


def track_prev_all(instr: Instruction, func: Func) -> list:
    '''
    return a list containing all previous instructions of an instruction
    parameters:
    - instr: the instruction need to be analyzed
    - func: the function containing the instr
    '''
    # func = emul.get_Func(func_name)
    ins = instr
    res = [ins]
    if is_constant_ins(ins):
        return res
    elif is_get_local_ins(ins):
        # the data comes from a local, usually no arg
        tmp = get_local_source(ins, func)
        if tmp is not None:
            ins = tmp
            res.append(ins)
        else:
            return res
    elif is_load_ins(ins):
        base_addr = instr.ssa.args
        tmp = get_memo_source()
        if tmp is not None:
            ins = tmp
            res.append(ins)
        else:
            # TODO: it is possible that cannot find the
            # source of a memo in the same function
            # currently skip this situation
            return res
    elif is_call_ins(ins):
        # TODO: interprocedural trace back
        return res
    if ins.ssa.args is not None:
        for arg in ins.ssa.args:
            res += track_prev_all(arg, func)
    return res


def track_next(instr: Instruction, ins_list: list) -> list:
    ins = track_next_one(instr, ins_list)
    for i in ins:
        ins += track_next(i, ins_list)
    return ins


def track_next_one(instr: Instruction, ins_list: list) -> list:
    ins = []
    for i in ins_list:
        if i.ssa is not None and type(i.ssa.args) == list:
            if instr in i.ssa.args:
                ins.append(i)
    return ins


def track_next_ssa(var: Instruction, ssa_list: list) -> list:
    res = []
    for s in ssa_list:
        if var in s.args:
            res.append(s)
    for s in res:
        res += track_next_ssa(s.asmt, ssa_list)
    return res


def get_locals(memo_instr: list) -> list:
    '''
    return a list containing all local names used in memory instructions
    parameter: a list containing memory instructions
    '''
    locals = []
    for i in memo_instr:
        pre_ins = track_prev(i.ssa.args[-1])  # second para
        for p in pre_ins:
            if 'local' in p.name or 'global' in p.name:
                addi(get_local_global_name(p), locals)
    return locals


'''
def get_local_dic(localssa: list) -> dict:
    
    # return a dictionary: keys are variables and values are the local names (ssa form)
    # parameter: a list including the ssa form local instructions
    
    local_dic = {}
    for i in localssa:
        i = str(i)
        if i[0] == '%':
            l, r = i.split(' = ')
            local_dic[l] = r
    return local_dic
'''


# EXTERNAL


def ex_fun(func: Func) -> list:
    # the number of import funcs
    # importn = len(func.emul.emul.ana.imports_func)
    importn = func.emul.get_import_len()
    res = []
    ins = func.func.instructions
    for _, i in enumerate(ins):
        if i.name == 'call':
            if int(i.operand_interpretation.split()[1]) < importn:
                continue    # ignore library (import) funcs
            if _+1 < len(ins) and ins[_+1].name == 'drop':
                continue    # ignore if drop the return value
            if i.ssa.args is None or i.ssa.new_assignement is None:
                continue    # ignore if no parameter or return value
            res.append(i)
    return res


def para_taint(func: Func) -> bool:
    # Step 1: detect the number of parameters
    f = func.func
    paras = func.get_param()
    n = len(paras)  # number of paras
    # printo(f)
    # print(n)
    # Step 2: select all instructions containing parameters
    locals = ['local %d' % i for i in range(n)]
    new_ins = []
    for i in f.instructions:
        for l in locals:
            # TODO: why need to add 'i.ssa is not None'??
            if i.ssa is not None and l in i.ssa.format() and 'get' in i.ssa.format():
                # printo(i)
                new_ins.append(i)
    # print('>>new_ins:')
    # prints(new_ins)
    related_ins = new_ins
    while len(new_ins) > 0:
        # Step 3: execute taint analysis upon para-related instructions
        for i in new_ins:
            tmp_ins = track_next(i, f.instructions)
            for t in tmp_ins:
                addi(t, related_ins)
        # print('>>related_ins:')
        # prints(related_ins)
        new_ins = []
        new_var = []
        for i in related_ins:
            if 'set' in i.name or 'tee' in i.name:
                tmp_var = i.operand_interpretation[i.operand_interpretation.index(
                    '_')+1:]
                if tmp_var not in locals and tmp_var not in new_var:
                    new_var.append((tmp_var, i))
                    locals.append(tmp_var)
        # print(new_var)
        for v in new_var:
            var, ins = v
            # print(ins.ssa.format())
            var_ssa = local_ssa(var, func.BNet)
            # print('>ssa of '+var+':')
            # printl(var_ssa)
            ssa_ins = track_next_ssa('%{:02X}'.format(
                ins.ssa.args[0].ssa.new_assignement), var_ssa)
            # print('>taint ssa:')
            # printl(ssa_ins)
            for i in ssa_ins:
                if i.data not in related_ins:
                    new_ins.append(i.data)
                    related_ins.append(i.data)
            # func.print_net()
    for i in func.return_values:
        if i in related_ins:
            return True
    return False


def external_check(func: Func):
    print('external check start:')
    exfunc = ex_fun(func)   # get the external functions
    # fns = ['$func%s' % f.operand_interpretation.split()[1] for f in exfunc]
    fns = [func.emul.get_func_name(
        f.operand_interpretation.split()[1]) for f in exfunc]
    print('Exfunc: ', fns)
    for f in exfunc:
        # fn = '$func%s' % f.operand_interpretation.split()[1]
        fn = func.emul.get_func_name(f.operand_interpretation.split()[1])
        print('>>'+fn)
        # res = para_taint(Func(func.emul, fn))
        res = para_taint(func.emul.get_Func(fn))
        print(res)
        set_dataflow(f, str(res))
    print('external check end.')

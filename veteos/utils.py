
from veteos.octopus.arch.wasm.instruction import Instruction
from veteos.octopus.arch.wasm.cfg import Function


def is_cmp_ins(ins: str):
    def is_eq(insname: str):
        return '.eq' in insname

    def is_ne(insname: str):
        return '.ne' in insname and 'neg' not in insname and 'nea' not in insname

    def is_lt(insname: str):
        return '.lt' in insname

    def is_gt(insname: str):
        return '.gt' in insname

    def is_le(insname: str):
        return '.le' in insname

    def is_ge(insname: str):
        return '.ge' in insname and 'get' not in insname
    return is_eq(ins) or is_ne(ins) or is_lt(ins) or is_gt(ins) or is_le(ins) or is_ge(ins)


def is_load_ins(instr: Instruction) -> bool:
    return 'load' in instr.name


def is_store_ins(instr: Instruction) -> bool:
    return 'store' in instr.name


def is_call_ins(instr: Instruction) -> bool:
    return 'call' in instr.name


def is_constant_ins(instr: Instruction) -> bool:
    try:
        return instr.ssa.is_constant
    except:
        return 'const' in instr.name


def is_get_local_ins(instr: Instruction) -> bool:
    return 'get_local' in instr.name


def get_local_global_name(instr: Instruction) -> str:
    return instr.operand_interpretation.split('_')[-1]


def get_ins_interpretation(ins: Instruction) -> str:
    '''
    return the operand_interpretation of an Instruction
    '''
    return ins.operand_interpretation if ins.operand_interpretation != None else ins.name


def is_db_find(fn: str) -> bool:
    return 'db_' in fn and ('find' in fn or 'upperbound' in fn or 'lowerbound' in fn or 'end' in fn)


def is_db_store(fn: str) -> bool:
    return 'db_' in fn and ('store' in fn or 'update' in fn)


def eosio_name_decoder(value: int) -> str:
    '''
    decode the 64-bit int to a string
    '''
    value = int(value)
    name = ''
    encoding = ".12345abcdefghijklmnopqrstuvwxyz"
    for i in range(59, 0, -5):
        index = (value >> i) & 31
        name += encoding[index]
    dots = 0
    for i in range(len(name)-1, -1, -1):
        if name[i] == '.':
            dots += 1
        else:
            break
    return name[:len(name)-dots]


def addi(item, list: list):
    if item not in list:
        list.append(item)


def set_dataflow(ins, data: str):
    ins.dataflow = ' [%s]' % data
    '''for i in func.func.instructions:
        if i == ins:
            i.dataflow = ' [%s]' % data'''

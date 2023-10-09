# from core import *
from veteos.terminal import *
from veteos.misc import *


class Analyzer:
    def ins2str(ins: Instruction, target: str = None):
        def add_note(itp: str):
            if '6138663591592764928' in itp:
                itp += ' ("eosio.token")'
            elif '-3617168760277827584' in itp:
                itp += ' ("transfer")'
            elif '3617214756542218240' in itp:
                itp += ' ("active")'
            elif target != None and target == 'apply' and 'local 1' in itp:
                itp += ' (code)'
            elif target != None and target == 'apply' and 'local 2' in itp:
                itp += ' (action)'
            elif target != None and 'call' in itp:
                itp += ' (%s)' % target
            elif 'i64.const' in itp:
                itp += ' ("%s")' % eosio_name_decoder(int(itp.split()[-1]))
            # convert to html
            return itp.replace('(', '<').replace(')', '>')
        itp = get_ins_interpretation(ins)
        itp = add_note(itp)
        return str(ins.offset)+': '+itp

    def find_call_ins(emul: Contract, funcname: str, target: str, full: bool = False, index_only: bool = False, reverse: bool = False, start_index: int = 0):
        func = emul.get_function(funcname)
        if func == None:
            print(funcname)
        instrs = func.instructions
        res = []
        for idx in (range(start_index, -1, -1) if reverse else range(start_index, len(instrs))):
            ins = instrs[idx]
            if 'call' in ins.name:
                fid = get_ins_interpretation(ins).split()[-1]
                tarname = emul.get_func_name(int(fid))
                if target in tarname or (target == 'db_find' and is_db_find(tarname)) or (target == 'db_store' and is_db_store(tarname)):
                    if index_only:
                        return idx
                    tmp = [
                        funcname+':'+Analyzer.ins2str(i, tarname) for i in instrs[max(idx-4, 0):idx+1]]
                    if full:
                        res.append(tmp)
                    else:
                        return tmp
        return res if len(res) > 0 else None

    def pay2play(emul: Contract):
        funcname = 'apply'
        app = emul.get_function(funcname)
        if app == None:
            return False
        eosio_token = False
        transfer = False
        res = {'eosio.token': None,
               'transfer': None}
        instrs = app.instructions
        for idx, ins in enumerate(instrs):
            if 'i64.const' in ins.name and (is_cmp_ins(instrs[idx+1].name) or is_cmp_ins(instrs[idx+2].name)):
                if not eosio_token and ins.operand == Const.EOSIO_TOKEN:
                    eosio_token = True
                    left, right = idx, min(idx+4, len(instrs))
                    if is_cmp_ins(instrs[idx+1].name):
                        left, right = max(left-1, 0), right-1
                    res['eosio.token'] = [
                        funcname+':' + Analyzer.ins2str(i, funcname) for i in instrs[left:right]]
                if not transfer and ins.operand == Const.TRANSFER:
                    transfer = True
                    left, right = idx, min(idx+4, len(instrs))
                    if is_cmp_ins(instrs[idx+1].name):
                        left, right = max(left-1, 0), right-1
                    res['transfer'] = [
                        funcname+':'+Analyzer.ins2str(i, funcname) for i in instrs[left:right]]
                if eosio_token and transfer:
                    return res
        return None

    def notify(emul: Contract):
        def inline_eos_trans(emul: Contract):
            '''
            similar to find_action_chain() in txn_ana()
            '''
            def find_strings(func: Function) -> dict:
                funcname = func.name
                eosio_token = False
                transfer = False
                active = False
                res = {'eosio.token': None,
                       'transfer': None,
                       'active': None}
                instrs = func.instructions
                for idx, ins in enumerate(instrs):
                    if 'i64.const' in ins.name and idx+1 < len(instrs) and 'i64.store' in instrs[idx+1].name:
                        if ins.operand == b'\x00':
                            continue
                        if not eosio_token and ins.operand == Const.EOSIO_TOKEN:
                            eosio_token = True
                            res['eosio.token'] = [
                                funcname+':'+Analyzer.ins2str(i, target) for i in instrs[idx:idx+2]]
                        if not transfer and ins.operand == Const.TRANSFER:
                            transfer = True
                            res['transfer'] = [
                                funcname+':'+Analyzer.ins2str(i, target) for i in instrs[idx:idx+2]]
                        if not active and ins.operand == Const.ACTIVE:
                            active = True
                            res['active'] = [
                                funcname+':'+Analyzer.ins2str(i, target) for i in instrs[idx:idx+2]]
                        if eosio_token and transfer and active:
                            return res
                return None

            target = 'send_inline'
            actions = find_func_from_tree(emul, target)
            for ac in actions:
                idx = len(ac)-2
                while idx >= 0:
                    func_name = ac[idx]
                    func = emul.get_function(func_name)
                    res = find_strings(func)
                    if res != None:
                        res['inline'] = Analyzer.find_call_ins(
                            emul, ac[-2], target)[-4:]
                        return res
                    idx -= 1
            return None

        receipt = 'require_recipient'
        res = {receipt: []}
        reci = emul.get_call_edges_to(receipt)
        if reci != None:
            rc = reci[-1]
            rc_ins = Analyzer.find_call_ins(emul, rc, receipt)[-2:]
            res[receipt] = rc_ins
        inline = inline_eos_trans(emul)
        res['eosio.token::transfer'] = inline
        if reci != None or inline != None:
            return res
        else:
            return None

    def stateIO(emul: Contract, read: bool = True, full=True):
        def find_db_find(flist: list) -> int:
            for i in range(len(flist)-1, -1, -1):
                if is_db_find(flist[i]):
                    return i
            return -1

        def find_caller_callee(flist: list, idx: int):
            caller, callee = -1, -1
            for i in range(idx-1, -1, -1):
                if is_db_find(flist[i]):
                    continue
                else:
                    caller = i
                    break
            for i in range(idx+1, len(flist)):
                if is_db_find(flist[i]):
                    continue
                else:
                    callee = i
                    break
            return caller, callee

        def find_caller(flist: list, idx: int):
            caller = -1
            for i in range(idx-1, -1, -1):
                if 'db_' in flist[i]:
                    continue
                else:
                    caller = i
                    break
            return caller
        dbfind = 'db_find'
        dbget = 'db_get' if read else 'db_store'
        dbr = find_db_from_tree(emul, dbget, full=True)
        # return dbr if len(dbr)>0 else None
        res = []
        if len(dbr) > 0:
            for ac in dbr:
                tmp = {dbfind: None,
                       dbget: None}
                idx = find_db_find(ac)
                if idx < 1:  # 'db_find' not found in the same chain
                    dbfs = find_func_from_tree_new(
                        emul, dbfind, cmp=lambda _, k: 'db_' in k and 'find_i' in k)
                    if len(dbfs) > 0:
                        dbf = dbfs[0]  # select the first chain
                        tmp[dbfind] = Analyzer.find_call_ins(
                            emul, dbf[-2], 'find_i')
                    if len(dbfs) == 0:  # 'db_find' not found, to find other finding APIs
                        dbfs = find_func_from_tree_new(
                            emul, dbfind, cmp=lambda _, k: is_db_find(k))
                        if len(dbfs) == 0:
                            continue
                        dbf = dbfs[0]  # select the first chain
                        tmp[dbfind] = Analyzer.find_call_ins(
                            emul, dbf[-2], dbfind)
                else:
                    caller, callee = find_caller_callee(ac, idx)
                    caller, callee = ac[caller], ac[callee]
                    # print(caller,callee)
                    # print(ac)
                    idx_cget = Analyzer.find_call_ins(
                        emul, caller, callee, index_only=True)
                    tmp[dbfind] = Analyzer.find_call_ins(
                        emul, caller, dbfind, reverse=True, start_index=idx_cget)
                    if tmp[dbfind] == None:
                        tmp[dbfind] = Analyzer.find_call_ins(
                            emul, caller, dbfind)
                    # tmp[dbfind]=Component.find_call_ins(emul,caller,dbfind,full=True)
                tmp[dbget] = Analyzer.find_call_ins(
                    emul, ac[find_caller(ac, len(ac)-1)], dbget)[-1]
                if not full and tmp[dbget] != None:
                    return tmp
                res.append(tmp)
        return res if len(res) > 0 else None

    def checkCondition(emul: Contract):
        def is_get_parameter(ins: Instruction, paran: int) -> bool:
            if 'get_local' in ins.name:
                para_index = ins.operand_interpretation.split()[1]
                if int(para_index) < paran:
                    return True
            return False

        def get_stack_size(instrs: list):
            for idx, ins in enumerate(instrs):
                if 'get_global' in ins.name and idx+2 < len(instrs):
                    if 'i32.const' in instrs[idx+1].name and 'i32.sub' in instrs[idx+2].name:
                        res = instrs[idx+1].operand_interpretation.split()[1]
                        return int(res)

        def is_load_parameter(ins: Instruction, stack_size: int, param_size: int) -> bool:
            if 'load' in ins.name and stack_size != None:
                offset = ins.operand_interpretation.split()[-1]
                offset = int(offset, 16) if offset.startswith(
                    '0x') else int(offset)
                if offset >= stack_size-param_size:
                    return True
            return False
        acs = emul.get_actions()
        for ac in acs:
            func = emul.get_function(ac)
            fn = func.prefered_name
            param = fn[fn.index('(')+1:fn.index(')')].split()
            paran = len(param)
            if paran < 1:
                continue
            param_size = 0
            for pa in param:
                if '32' in pa:
                    param_size += 4
                elif '64' in pa:
                    param_size += 8
            instrs = func.instructions
            stack_size = get_stack_size(instrs)
            for idx, ins in enumerate(instrs):
                if is_get_parameter(ins, paran) or is_load_parameter(ins, stack_size, param_size):
                    if idx+1 < len(instrs) and is_cmp_ins(instrs[idx+1].name):
                        end = idx+1
                    elif idx+2 < len(instrs) and is_cmp_ins(instrs[idx+2].name):
                        end = idx+2
                    else:
                        continue
                    res = []
                    for idxx, inss in enumerate(instrs[end-2:end+2]):
                        tmps = ''
                        if inss == instrs[idx]:
                            tmps = ' <user input>'
                        elif idxx < 2:
                            tmps = ' <global state>'
                        res.append(ac+':'+Analyzer.ins2str(inss)+tmps)
                    return res
        return None

    def createSecret(emul: Contract, full=False):
        '''
        similar to rem_ana()
        '''
        def write_rem(emul: Contract, funcname: str, full: bool = False):
            func = emul.get_function(funcname)
            if func == None:
                return False
            res = []
            tmp = []
            # tmp_idx=0
            for i in func.instructions:
                if '.rem_' in i.name:
                    tmp = [funcname+':'+Analyzer.ins2str(i)]
                    # tmp_idx=0
                elif len(tmp) == 1 and ('set' in i.name or 'store' in i.name):
                    # if tmp_idx>3: # threshold
                    #     continue
                    tmp.append(funcname+':'+Analyzer.ins2str(i))
                    if not full:
                        return tmp
                    res.append(tmp)
                    tmp = []
                # tmp_idx+=1
            return res if len(res) > 0 else None

        acns = emul.get_all_function_names()    # all funcs
        for acn in acns:
            res = write_rem(emul, acn, full)
            if res != None:
                return res
        return None


class Analyzerssa:
    def ins_preprocess(func: Func, left, right):
        for i in range(left, right):
            ins = func.func.instructions[i]
            if 'local' in ins.name and ins.dataflow == None:
                func.set_local_ssa(get_ins_interpretation(ins).split()[-1])
        return func.func.instructions[left:right]

    def ins2str(ins: Instruction, target: str = None):
        def add_note(itp: str):
            res = ''
            if '6138663591592764928' in itp:
                res += ' <"eosio.token">'
            elif '-3617168760277827584' in itp:
                res += ' <"transfer">'
            elif '3617214756542218240' in itp:
                res += ' <"active">'
            elif target != None and target == 'apply' and 'local 1' in itp:
                res += ' <code>'
            elif target != None and target == 'apply' and 'local 2' in itp:
                res += ' <action>'
            elif target != None and 'call' in itp:
                res += ' <%s>' % target
            elif 'i64.const' in itp:
                res += ' <"%s">' % eosio_name_decoder(int(itp.split()[-1]))
            # convert to html
            return res.replace('<', '&lt;').replace('>', '&gt;')
        itp = ins.ssa.format() if ins.ssa != None else get_ins_interpretation(ins)
        # if ins.dataflow!=None:
        #     itp+=ins.dataflow
        itp += add_note(get_ins_interpretation(ins))
        return str(ins.offset)+': '+itp

    def find_call_ins(emul: Contract, funcname: str, target: str, full: bool = False, index_only: bool = False, reverse: bool = False, start_index: int = 0):
        # func=emul.get_function(funcname)
        func = get_func_wrapper(emul, funcname)
        if func == None:
            print(funcname)
        # instrs=func.instructions
        instrs = func.func.instructions
        res = []
        for idx in (range(start_index, -1, -1) if reverse else range(start_index, len(instrs))):
            ins = instrs[idx]
            if 'call' in ins.name:
                fid = get_ins_interpretation(ins).split()[-1]
                tarname = emul.get_func_name(int(fid))
                if target in tarname or (target == 'db_find' and is_db_find(tarname)) or (target == 'db_store' and is_db_store(tarname)):
                    if index_only:
                        return idx
                    tmp = [
                        funcname+':'+Analyzer.ins2str(i, tarname) for i in instrs[max(idx-4, 0):idx+1]]
                    if full:
                        res.append(tmp)
                    else:
                        return tmp
        return res if len(res) > 0 else None

    def pay2play(emul: Contract):
        funcname = 'apply'
        # app=emul.get_function(funcname)
        try:
            app = get_func_wrapper(emul, funcname)
            instrs = app.func.instructions
        except:
            app = emul.get_function(funcname)
            instrs = app.instructions
        if app == None:
            return False
        eosio_token = False
        transfer = False
        res = {'eosio.token': None,
               'transfer': None}
        for idx, ins in enumerate(instrs):
            if 'i64.const' in ins.name and (is_cmp_ins(instrs[idx+1].name) or is_cmp_ins(instrs[idx+2].name)):
                if not eosio_token and ins.operand == Const.EOSIO_TOKEN:
                    eosio_token = True
                    left, right = idx, min(idx+4, len(instrs))
                    if is_cmp_ins(instrs[idx+1].name):
                        left, right = max(left-1, 0), right-1
                    # res['eosio.token']=[funcname+':'+ Component.ins2str(i,funcname) for i in Component.ins_preprocess(app,left,right)]
                    res['eosio.token'] = [
                        funcname+':' + Analyzer.ins2str(i, funcname) for i in instrs[left:right]]
                if not transfer and ins.operand == Const.TRANSFER:
                    transfer = True
                    left, right = idx, min(idx+4, len(instrs))
                    if is_cmp_ins(instrs[idx+1].name):
                        left, right = max(left-1, 0), right-1
                    # res['transfer']=[funcname+':'+Component.ins2str(i,funcname) for i in Component.ins_preprocess(app,left,right)]
                    res['transfer'] = [
                        funcname+':'+Analyzer.ins2str(i, funcname) for i in instrs[left:right]]
                if eosio_token and transfer:
                    return res
        return None

    def notify(emul: Contract):
        def inline_eos_trans(emul: Contract):
            '''
            similar to find_action_chain() in txn_ana()
            '''
            def find_strings(func: Function) -> dict:
                funcname = func.name
                eosio_token = False
                transfer = False
                active = False
                res = {'eosio.token': None,
                       'transfer': None,
                       'active': None}
                instrs = func.instructions
                id1, id2, id3 = -1, -1, -1
                for idx, ins in enumerate(instrs):
                    if 'i64.const' in ins.name and idx+1 < len(instrs) and 'i64.store' in instrs[idx+1].name:
                        if ins.operand == b'\x00':
                            continue
                        if not eosio_token and ins.operand == Const.EOSIO_TOKEN:
                            eosio_token = True
                            id1 = idx
                        if not transfer and ins.operand == Const.TRANSFER:
                            transfer = True
                            id2 = idx
                        if not active and ins.operand == Const.ACTIVE:
                            active = True
                            id3 = idx
                        if eosio_token and transfer and active:
                            # TODO: Octopus bug
                            try:
                                app = get_func_wrapper(emul, funcname)
                                instrs = app.func.instructions
                            except:
                                instrs = func.instructions
                            res['eosio.token'] = [
                                funcname+':'+Analyzer.ins2str(i, target) for i in instrs[id1:id1+2]]
                            res['transfer'] = [
                                funcname+':'+Analyzer.ins2str(i, target) for i in instrs[id2:id2+2]]
                            res['active'] = [
                                funcname+':'+Analyzer.ins2str(i, target) for i in instrs[id3:id3+2]]
                            return res
                return None

            target = 'send_inline'
            actions = find_func_from_tree(emul, target)
            for ac in actions:
                idx = len(ac)-2
                while idx >= 0:
                    func_name = ac[idx]
                    func = emul.get_function(func_name)
                    res = find_strings(func)
                    if res != None:
                        res['inline'] = Analyzer.find_call_ins(
                            emul, ac[-2], target)[-4:]
                        return res
                    idx -= 1
            return None

        receipt = 'require_recipient'
        res = {receipt: []}
        reci = emul.get_call_edges_to(receipt)
        if reci != None:
            rc = reci[-1]
            rc_ins = Analyzer.find_call_ins(emul, rc, receipt)[-2:]
            res[receipt] = rc_ins
        inline = inline_eos_trans(emul)
        res['eosio.token::transfer'] = inline
        if reci != None or inline != None:
            return res
        else:
            return None

    def stateIO(emul: Contract, read: bool = True, full=True):
        def find_db_find(flist: list) -> int:
            for i in range(len(flist)-1, -1, -1):
                if is_db_find(flist[i]):
                    return i
            return -1

        def find_caller_callee(flist: list, idx: int):
            caller, callee = -1, -1
            for i in range(idx-1, -1, -1):
                if is_db_find(flist[i]):
                    continue
                else:
                    caller = i
                    break
            for i in range(idx+1, len(flist)):
                if is_db_find(flist[i]):
                    continue
                else:
                    callee = i
                    break
            return caller, callee

        def find_caller(flist: list, idx: int):
            caller = -1
            for i in range(idx-1, -1, -1):
                if 'db_' in flist[i]:
                    continue
                else:
                    caller = i
                    break
            return caller
        dbfind = 'db_find'
        dbget = 'db_get' if read else 'db_store'
        dbr = find_db_from_tree(emul, dbget, full=True)
        # return dbr if len(dbr)>0 else None
        res = []
        if len(dbr) > 0:
            for ac in dbr:
                tmp = {dbfind: None,
                       dbget: None}
                idx = find_db_find(ac)
                if idx < 1:  # 'db_find' not found in the same chain
                    dbfs = find_func_from_tree_new(
                        emul, dbfind, cmp=lambda _, k: 'db_' in k and 'find_i' in k)
                    if len(dbfs) > 0:
                        dbf = dbfs[0]  # select the first chain
                        tmp[dbfind] = Analyzer.find_call_ins(
                            emul, dbf[-2], 'find_i')
                    if len(dbfs) == 0:  # 'db_find' not found, to find other finding APIs
                        dbfs = find_func_from_tree_new(
                            emul, dbfind, cmp=lambda _, k: is_db_find(k))
                        if len(dbfs) == 0:
                            continue
                        dbf = dbfs[0]  # select the first chain
                        tmp[dbfind] = Analyzer.find_call_ins(
                            emul, dbf[-2], dbfind)
                else:
                    caller, callee = find_caller_callee(ac, idx)
                    caller, callee = ac[caller], ac[callee]
                    # print(caller,callee)
                    # print(ac)
                    idx_cget = Analyzer.find_call_ins(
                        emul, caller, callee, index_only=True)
                    tmp[dbfind] = Analyzer.find_call_ins(
                        emul, caller, dbfind, reverse=True, start_index=idx_cget)
                    if tmp[dbfind] == None:
                        tmp[dbfind] = Analyzer.find_call_ins(
                            emul, caller, dbfind)
                    # tmp[dbfind]=Component.find_call_ins(emul,caller,dbfind,full=True)
                tmp[dbget] = Analyzer.find_call_ins(
                    emul, ac[find_caller(ac, len(ac)-1)], dbget)[-1]
                if not full and tmp[dbget] != None:
                    return tmp
                res.append(tmp)
        return res if len(res) > 0 else None

    def checkCondition(emul: Contract):
        def is_get_parameter(ins: Instruction, paran: int) -> bool:
            if 'get_local' in ins.name:
                para_index = ins.operand_interpretation.split()[1]
                if int(para_index) < paran:
                    return True
            return False

        def get_stack_size(instrs: list):
            for idx, ins in enumerate(instrs):
                if 'get_global' in ins.name and idx+2 < len(instrs):
                    if 'i32.const' in instrs[idx+1].name and 'i32.sub' in instrs[idx+2].name:
                        res = instrs[idx+1].operand_interpretation.split()[1]
                        return int(res)

        def is_load_parameter(ins: Instruction, stack_size: int, param_size: int) -> bool:
            if 'load' in ins.name and stack_size != None:
                offset = ins.operand_interpretation.split()[-1]
                offset = int(offset, 16) if offset.startswith(
                    '0x') else int(offset)
                if offset >= stack_size-param_size:
                    return True
            return False
        acs = emul.get_actions()
        for ac in acs:
            func = emul.get_function(ac)
            instrs = func.instructions
            fn = func.prefered_name
            param = fn[fn.index('(')+1:fn.index(')')].split()
            paran = len(param)
            if paran < 1:
                continue
            param_size = 0
            for pa in param:
                if '32' in pa:
                    param_size += 4
                elif '64' in pa:
                    param_size += 8
            stack_size = get_stack_size(instrs)
            for idx, ins in enumerate(instrs):
                if is_get_parameter(ins, paran) or is_load_parameter(ins, stack_size, param_size):
                    if idx+1 < len(instrs) and is_cmp_ins(instrs[idx+1].name):
                        end = idx+1
                    elif idx+2 < len(instrs) and is_cmp_ins(instrs[idx+2].name):
                        end = idx+2
                    else:
                        continue
                    try:
                        func = get_func_wrapper(emul, ac)  # Func
                        instrs = func.func.instructions
                    except:
                        func = emul.get_function(ac)
                        instrs = func.instructions
                    res = []
                    for idxx, inss in enumerate(instrs[end-2:end+2]):
                        tmps = ''
                        if inss == instrs[idx]:
                            tmps = ' <user input>'
                        elif idxx < 2:
                            tmps = ' <global state>'
                        res.append(ac+':'+Analyzer.ins2str(inss)+tmps)
                    return res
        return None

    def createSecret(emul: Contract, full=False):
        '''
        similar to rem_ana()
        '''
        def write_rem(emul: Contract, funcname: str, full: bool = False):
            try:
                func = get_func_wrapper(emul)
                func = func.func
            except:
                func = emul.get_function(funcname)
            if func == None:
                return False
            res = []
            tmp = []
            # tmp_idx=0
            for i in func.instructions:
                if '.rem_' in i.name:
                    tmp = [funcname+':'+Analyzer.ins2str(i)]
                    # tmp_idx=0
                elif len(tmp) == 1 and ('set' in i.name or 'store' in i.name):
                    # if tmp_idx>3: # threshold
                    #     continue
                    tmp.append(funcname+':'+Analyzer.ins2str(i))
                    if not full:
                        return tmp
                    res.append(tmp)
                    tmp = []
                # tmp_idx+=1
            return res if len(res) > 0 else None

        acns = emul.get_all_function_names()    # all funcs
        for acn in acns:
            res = write_rem(emul, acn, full)
            if res != None:
                return res
        return None


class Solver:
    def __init__(self, emul: Contract) -> None:
        self.emul = emul

    def list2str(self, raw: list, c: str = ':'):
        # if len(raw) == 0:
        #     return ''
        title = raw[0].split(c)[0]+c
        return title+('\l' if not title.endswith('\l') else '') + ('\l'.join(raw)).replace(title, '')

    def str2html(self, s: str, title: str):
        if s.endswith('\l'):
            s = s[:-2]
        fs = 16
        s = s.replace('<', '&lt;').replace('>', '&gt;')
        return '<<table border="0" cellborder="0">\
            <tr><td><font point-size="%d" color="blue">&lt;%s&gt;</font></td></tr>\
                <tr><td align="left"><font point-size="%d">%s</font></td></tr></table>>'\
        % (fs, title, fs, s.replace('\l', '</font></td></tr><tr><td align="left"><font point-size="%d">' % fs)
           .replace('&lt;', '</font><font point-size="%d" color="orange">&lt;' % fs))

    def pay2play_wp(self):
        raw = Analyzer.pay2play(self.emul)
        if raw == None:
            return 'None'
        res = raw['eosio.token']+raw['transfer']
        return self.list2str(res)+'\l'

    def checkCondition_wp(self):
        raw = Analyzer.checkCondition(self.emul)
        if raw == None:
            return 'None'
        return self.list2str(raw)+'\l'

    def createSecret_wp(self):
        # only works for 'rem'
        raw = Analyzer.createSecret(self.emul)
        if raw == None:
            return 'None'
        return self.list2str(raw)+'\l'

    def notify_wp(self):
        raw = Analyzer.notify(self.emul)
        if raw == None:
            return 'None'
        res = ''
        ts = raw['eosio.token::transfer']
        rc = raw['require_recipient']
        tmp = []
        if ts != None:
            for k in ['eosio.token', 'transfer', 'active',]:
                tmp.append(ts[k][0])
            res = [self.list2str(tmp)]
            res.append(self.list2str([ts['inline'][-1]]))
            res = self.list2str(res, '\l')
        if len(rc) > 0:
            res += self.list2str([rc[-1]])
        return res+'\l'

    def stateIO_wp(self):
        def dic_ana(raw: list):
            '''
            return a dict whose keys are table names
            '''
            res = {}
            dbg = 'db_get'
            dbs = 'db_store'
            for dc in raw:
                dbf = dc['db_find']
                key = dbf[-3].split()[-1]
                if key not in res.keys():
                    dbt = dc[dbg] if dbg in dc.keys() else dc[dbs]
                    res[key] = '\l'.join(
                        [self.list2str([dbf[-3], dbf[-1]]), self.list2str([dbt])])
                else:
                    continue
            return res
        rd = Analyzer.stateIO(self.emul)
        wt = Analyzer.stateIO(self.emul, read=False)
        if rd == None or wt == None:
            return 'None', 'None', 'None'
        rdd = dic_ana(rd)
        wtd = dic_ana(wt)
        tmp = ''
        rddk = list(rdd.keys())
        wtdk = list(wtd.keys())
        for k in rddk:
            if k in wtdk:
                tmp = k
                break
        secret = wtdk[1] if len(wtdk) > 1 else wtdk[0]
        if tmp != '':
            if secret == tmp and len(wtdk) > 1:
                secret = wtdk[0]
            return rdd[tmp]+'\l', wtd[tmp]+'\l', wtd[secret]+'\l'
        else:
            return rdd[rddk[0]]+'\l', wtd[wtdk[0]]+'\l', wtd[secret]+'\l'

    def graph_viz(self, filename=None, dump_text=False, dump_graph=True):
        def viz(filename='summary.gv', TB=True):
            from graphviz import Digraph

            def T1():
                with g.subgraph(name='cluster_T1') as c:
                    # c.attr(rank='min')
                    c.attr(label='T1')
                    c.node('createSecret', label=n3)
                    c.node('actionT1m', label='<actionT1m>')
                    c.node('actionT1n', label='<actionT1n>')
                    c.edge('createSecret', 'actionT1m')
                    c.edge('actionT1m', 'actionT1n')

            def T2():
                with g.subgraph(name='cluster_T2') as c:
                    # c.attr(rank='same')
                    c.attr(label='T2')
                    c.node('payToPlay', label=n1)
                    c.node('checkCondition', label=n2)
                    c.node('writeState', label=n4)
                    c.node('notify', label=n5)
                    c.edge('payToPlay', 'checkCondition')
                    c.edge('checkCondition', 'writeState')
                    c.edge('checkCondition', 'notify')
                    c.edge('writeState', 'notify')

            def T3():
                with g.subgraph(name='cluster_T3') as c:
                    # c.attr(rank='max')
                    c.attr(label='T3')
                    c.node('readState', label=n6)
                    c.node('actionT3m', label='<actionT3m>')
                    c.node('actionT3n', label='<actionT3n>')
                    c.edge('readState', 'actionT3m')
                    c.edge('actionT3m', 'actionT3n')
            g = Digraph('G', filename=filename)
            g.attr(overlap='scale')
            g.attr(splines='polyline')
            g.attr(ratio='fill')
            g.attr('node', shape='rectangle')
            g.attr('node', fontsize='16')
            g.attr('graph', style='dashed', color='darkgrey', fontsize='16.0'
                   # ,rankdir='LR'
                   )
            if TB:
                g.attr(rankdir='TB')
                T1()
                T2()
                T3()
            else:
                g.attr(rankdir='LR')
                T3()
                T2()
                T1()
            g.render(filename, view=False)
            return

        thisfile = self.emul.filename.split(os.path.sep)[-1]
        n1 = self.pay2play_wp()
        n2 = self.checkCondition_wp()
        n3 = self.createSecret_wp()
        n6, n4, secret = self.stateIO_wp()
        n5 = self.notify_wp()
        n3 = secret if n3 == 'None' else n3

        result_str = ['Detected Vulnerability Patterns:', 'F1 (Revertable):', n1[:-2], n5, 'F2 (Unpredictably Profitable):',
                      n3, 'F3 (Information Leakage):', n4[:-2], n6, 'F4 (Causal Inference):', n2]
        result_str = '\n'.join(result_str).replace('\l', '\n')
        vul_flag = True
        for pattern in [n1, n2, n3, n4, n5, n6]:
            if pattern == "None":
                vul_flag = False
                break
        if vul_flag:
            result_str += '\nResult:\nDetected Groundhog Day Vulnerability in file %s\nCode:1' % thisfile
        else:
            result_str += '\nResult:\nNo Groundhog Day Vulnerability in file %s\nCode:0' % thisfile
        print(result_str)

        result_dir = 'results'
        if not os.path.exists(result_dir):
            os.makedirs(result_dir)
        if dump_text:
            with open(os.path.join(result_dir, thisfile+'.log'), 'w') as wlog:
                wlog.write(result_str)
        if not dump_graph:
            return vul_flag

        t1 = 'payToPlay'
        t2 = 'checkCondition'
        t3 = 'createSecret'
        t4 = 'writeState'
        t5 = 'notify'
        t6 = 'readState'
        n1 = self.str2html(n1, t1)
        n2 = self.str2html(n2, t2)
        n3 = self.str2html(n3, t3)
        n4 = self.str2html(n4, t4)
        n5 = self.str2html(n5, t5)
        n6 = self.str2html(n6, t6)

        if filename == None:
            filename = thisfile
        viz(os.path.join(result_dir, filename+'.gv'))
        return vul_flag


def find_func_from_tree(emul: Contract, target: str, passes: str = None, full: bool = False) -> list:
    def dfs(node: dict, visited: list) -> list:
        res = []
        if type(node) != dict:
            return []
        for k in node.keys():
            if passes != None and passes in k:
                visited += [k]
            elif type(target) == str and target in k:
                return [visited+[k]]
            else:
                res += dfs(node[k], visited+[k])
        return res

    def bfs_full(node: dict, visited: list, res: list):
        if type(node) != dict:
            return
        tmp = []
        for k in node.keys():
            if passes != None and passes in k:
                visited += [k]
            elif target in k:
                res += [visited+[k]]
            else:
                tmp.append(k)
        for k in tmp:
            bfs_full(node[k], visited+[k], res)
        return

    res = []
    tree = func_call_tree(emul)
    if full:
        bfs_full(tree, [], res)
    else:
        res = dfs(tree, [])
    return res


def find_db_from_tree(emul: Contract, target: str, full: bool = False) -> list:
    def dfs(node: dict, visited: list) -> list:
        res = []
        if type(node) != dict:
            return []
        for k in node.keys():
            if is_db_find(k):
                visited += [k]
            elif target in k or (target == 'db_store' and is_db_store(k)):
                return [visited+[k]]
            else:
                res += dfs(node[k], visited+[k])
        return res

    def bfs_full(node: dict, visited: list, res: list):
        if type(node) != dict:
            return
        tmp = []
        for k in node.keys():
            if is_db_find(k):
                visited += [k]
            elif target in k or (target == 'db_store' and is_db_store(k)):
                res += [visited+[k]]
            else:
                tmp.append(k)
        for k in tmp:
            bfs_full(node[k], visited+[k], res)
        return

    res = []
    tree = func_call_tree(emul)
    if full:
        bfs_full(tree, [], res)
    else:
        res = dfs(tree, [])
    return res


def find_func_from_tree_new(emul: Contract, target: str, passes: str = None, full: bool = False, cmp=lambda t, k: t in k) -> list:
    def dfs(node: dict, visited: list) -> list:
        res = []
        if type(node) != dict:
            return []
        for k in node.keys():
            if passes != None and passes in k:
                visited += [k]
            elif cmp(target, k):
                return [visited+[k]]
            else:
                res += dfs(node[k], visited+[k])
        return res

    def bfs_full(node: dict, visited: list, res: list):
        if type(node) != dict:
            return
        tmp = []
        for k in node.keys():
            if passes != None and passes in k:
                visited += [k]
            elif cmp(target, k):
                res += [visited+[k]]
            else:
                tmp.append(k)
        for k in tmp:
            bfs_full(node[k], visited+[k], res)
        return

    res = []
    tree = func_call_tree(emul)
    if full:
        bfs_full(tree, [], res)
    else:
        res = dfs(tree, [])
    return res

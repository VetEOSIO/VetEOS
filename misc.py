import os


class Const:
    EOSIO_TOKEN = b'\x80\xcc\x8a\xa4\xb3\xc0\xba\x98\xd5\x00'  # eosio.token
    TRANSFER = b'\x80\x80\x80\xb8\xd5\x85\xcf\xe6M'  # transfer
    ACTIVE = b'\x80\x80\x80\x80\x80\xb5\xbb\x992'  # active


# custom timeout error
# class TimeoutError(Exception):
#     def __init__(self, msg):
#         super(TimeoutError, self).__init__()
#         self.msg = msg


EXM = 'examples/gamble.wasm'


def get_file_list(dir_path: str, ends: str = None) -> list:
    res = []
    dir_files = os.listdir(dir_path)  # get file list
    dir_files.sort()
    for file in dir_files:
        file_path = os.path.join(dir_path, file)  # combine path
        if os.path.isfile(file_path):
            if ends != None and not file_path.endswith(ends):
                continue
            res.append(os.path.abspath(file_path))
    return res


def printl(list: list):
    for i in list:
        print(str(i))


def prints(ssa: list):
    for i in ssa:
        print(i.ssa.format())


def printo(obj):
    print('\n'.join(['%s:%s' % item for item in obj.__dict__.items()]))


def printdic(dic: dict):
    sp = ' '

    def list2str(lst: list, level: int):
        res = '[\n'
        items = [str(i) for i in lst]
        res += ',\n'.join(items)
        res += '\n]'
        return res

    def dic2str(dic: dict, level: int):
        res = '{\n'
        items = []
        for k in dic.keys():
            # TODO: level
            # tmp += sp*level
            tmp = str(k)+': '
            if type(dic[k]) == dict:
                tmp += '\n'
                tmp += dic2str(dic[k], level+1)
            elif type(dic[k]) == list:
                tmp += '\n'
                tmp += list2str(dic[k], level+1)
            else:
                tmp += str(dic[k])
            items.append(tmp)
        res += ',\n'.join(items)
        res += '\n}'
        return res
    ret = dic2str(dic, 1)
    print(ret)
    return ret

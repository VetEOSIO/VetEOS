from veteos.core import *
from veteos.component import *

def test():
    filename='examples/gamble.wasm'
    emul=get_emul_wrapper(filename)
    g=ComGraph(emul)
    g.component_viz()

if __name__ == "__main__":
    test()
from veteos.core import *
from veteos.component import *

def test_detect():
    filename='examples/gamble.wasm'
    emul=get_emul_wrapper(filename)
    g=ComGraph(emul)
    g.component_viz()
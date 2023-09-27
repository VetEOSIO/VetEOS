import argparse

def main():
    parser = argparse.ArgumentParser(description="Security Analysis tool for EOSIO Smart Contracts in WebAssembly format.")
    
    # Define the arguments
    parser.add_argument("-f", "--file", type=str,
                        help='binary file (.wasm)',
                        metavar='WASMMODULE')
    parser.add_argument("-g", "--graph", action="store_true", help="generate the analysis summary graph")
    parser.add_argument("-s", "--shell", action="store_true", help="run vetEOS terminal")
    parser.add_argument("-t", "--test", action="store_true", help="run test cases")
    
    args = parser.parse_args()
    
    graph = None
    if args.file:
        # print("File path:", args.file)
        if args.graph:
            if args.test:
                from test_cases import test_detect
                test_detect()
                return
            graph=True
            from veteos.core import get_emul_wrapper
            from veteos.component import ComGraph
            emul=get_emul_wrapper(args.file)
            g=ComGraph(emul)
            g.component_viz()
            

    if not args.file and args.shell:
        from veteos.terminal import Terminal
        Terminal().run()


    if not args.file and not args.shell:
        parser.print_help()

if __name__ == "__main__":
    main()

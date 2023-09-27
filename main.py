import argparse

def main():
    parser = argparse.ArgumentParser(description="Security Analysis tool for EOSIO Smart Contracts in WebAssembly format.")
    
    # Define the arguments
    parser.add_argument("-f", "--file", type=argparse.FileType('rb'),
                        help='binary file (.wasm)',
                        metavar='WASMMODULE')
    parser.add_argument("-g", "--graph", action="store_true", help="generate the analysis summary graph")
    parser.add_argument("-t", "--terminal", action="store_true", help="run vetEOS terminal")
    
    args = parser.parse_args()
    
    graph = None
    if args.file:
        print("File path:", args.file)
        if args.graph:
            graph=True

    if not args.file and args.terminal:
        from veteos.terminal import Terminal
        Terminal().run()

    if not args.file and not args.terminal:
        parser.print_help()

if __name__ == "__main__":
    main()

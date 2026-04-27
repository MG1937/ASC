import time
t_start = time.perf_counter()

import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description="Extract and rebuild a specific class from a DEX file.")
    parser.add_argument("dex_path", help="Path to the input DEX file.")
    parser.add_argument("dalvik_class", help="The Dalvik format class name to extract (e.g., Lcom/poc/Main;).")
    parser.add_argument("--debug", action="store_true", help="Enable debug profiling output.")
    
    args = parser.parse_args()
    
    try:
        from core.dex.dex_manager import DexManager
        manager = DexManager(args.dex_path, debug=args.debug)
        new_dex_bytes = manager.extract_and_rebuild(args.dalvik_class)
        
        if args.debug:
            t_rebuild_end = time.perf_counter()
        from utils.decompiler import decompile_dex_bytes
        source_code = decompile_dex_bytes(new_dex_bytes, args.dalvik_class)
        
        t_end = time.perf_counter()
        
        if args.debug:
            print(f"[DEBUG] Dex Decompile Time: {(t_end - t_rebuild_end)*1000000:.2f} us")
            print(f"[DEBUG] Total Execution Time: {(t_end - t_start)*1000000:.2f} us")
            print("-" * 50)
            
        print(source_code)
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()

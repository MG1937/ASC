import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

def main():
    from dex_agent.cli.args import parse_args
    args = parse_args()
    t_start = time.perf_counter() if getattr(args, "verbose", False) else None

    from dex_agent.cli.presenter import print_success, print_error
    from dex_agent.app.usecases.get_class import execute_get_class
    from dex_agent.infra.config_store import ConfigStore
    from dex_agent.domain.errors import AgentException
    
    if args.command == "getclass":
        try:
            config_store = ConfigStore()
            
            result_code = execute_get_class(
                apk_path=args.apk_path,
                clazz_name=args.clazz,
                config_store=config_store,
                verbose=args.verbose,
                threads=args.threads,
            )
            
            if result_code.startswith("Class not found") or result_code.startswith("Failed"):
                print_error(result_code)
                sys.exit(1)
                
            print_success(result_code)
            
        except AgentException as e:
            print_error(str(e))
            sys.exit(1)
        except Exception as e:
            print_error(f"Unexpected error: {str(e)}")
            import traceback
            traceback.print_exc()            
            sys.exit(1)
        finally:
            if t_start is not None:
                elapsed = time.perf_counter() - t_start
                print(f"[PERF] Total wall time: {elapsed:.3f}s")

if __name__ == "__main__":
    main()

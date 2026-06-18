from dex_agent.domain.models import ClassName
from dex_agent.infra.shell import run_command

def locate_dex_class(dex_file: str, clazz_name: str, dexdump_bin: str) -> bool:
    clazz = ClassName(clazz_name)
    
    command = f'"{dexdump_bin}" -f -n "{dex_file}" | grep "Class descriptor.\\+{clazz.formatted}"'
    
    retcode, stdout, stderr = run_command(command, check=False)
    
    return bool(stdout.strip())

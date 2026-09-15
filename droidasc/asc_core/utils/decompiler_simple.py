def decompile_dex_bytes(dex_bytes: bytearray, dalvik_class_fmt: str):
    """
    Take DEX bytes and a target class format, decompile it using Androguard DAD
    and return the source code.
    """
    # Lazy import androguard to avoid massive cold-start penalty
    # when the decompiler is not strictly needed.
    from loguru import logger
    logger.remove()
    
    # Hack: Monkey patch heavy/unnecessary modules before importing androguard
    import sys
    class DummyClass: pass
    class DummyModule:
        __path__ = []
        def __init__(self):
            self.APK = DummyClass
        def __getattr__(self, name): return DummyModule()
        def __iter__(self): return iter([])
        def __call__(self, *args, **kwargs): return DummyModule()
        
    sys.modules['androguard.core.apk'] = DummyModule()
    sys.modules['networkx'] = DummyModule()
    sys.modules['pygments'] = DummyModule()
    sys.modules['lxml'] = DummyModule()
    sys.modules['asn1crypto'] = DummyModule()
    sys.modules['asn1crypto.x509'] = DummyModule()
    sys.modules['cryptography'] = DummyModule()
    sys.modules['matplotlib'] = DummyModule()
    sys.modules['pydot'] = DummyModule()
    sys.modules['IPython'] = DummyModule()
    sys.modules['colorama'] = DummyModule()
    sys.modules['dateutil'] = DummyModule()
    sys.modules['urllib3'] = DummyModule()
    sys.modules['requests'] = DummyModule()
    sys.modules['idna'] = DummyModule()
    sys.modules['chardet'] = DummyModule()
    sys.modules['certifi'] = DummyModule()
    sys.modules['pkg_resources'] = DummyModule()
    
    sys.modules['loguru'] = DummyModule()
    sys.modules['loguru._logger'] = DummyModule()
    sys.modules['click'] = DummyModule()
    sys.modules['urllib'] = DummyModule()
    sys.modules['urllib.request'] = DummyModule()
    sys.modules['http.client'] = DummyModule()
    sys.modules['email'] = DummyModule()
    sys.modules['email.parser'] = DummyModule()
    sys.modules['email.message'] = DummyModule()
    sys.modules['multiprocessing'] = DummyModule()
    sys.modules['multiprocessing.context'] = DummyModule()
    sys.modules['multiprocessing.reduction'] = DummyModule()
    sys.modules['xml.sax.saxutils'] = DummyModule()
    
    from androguard.core.dex import DEX
    from androguard.decompiler import decompile

    # Hack: Monkey patch the dataflow module directly to disable the slow passes entirely
    import androguard.decompiler.dataflow as dataflow
    
    # We replace the heaviest passes with no-ops
    def no_op(*args, **kwargs):
        pass
        
    dataflow.register_propagation = no_op
    dataflow.dead_code_elimination = no_op
    decompile.register_propagation = no_op
    decompile.dead_code_elimination = no_op
    
    # We also completely disable ALL androguard loggers via python's standard logging module
    import logging
    
    # Create a filter that blocks ALL records
    class BlockAllFilter(logging.Filter):
        def filter(self, record):
            return False

    block_filter = BlockAllFilter()
    
    for log_name in [
        'androguard.decompiler.dataflow',
        'androguard.decompiler.decompile',
        'androguard.decompiler.opcode_ins',
        'androguard.core.dex',
        'androguard.core.analysis.analysis',
        'androguard.core.bytecodes.dvm',
        'androguard'
    ]:
        log = logging.getLogger(log_name)
        log.setLevel(logging.CRITICAL)
        log.propagate = False
        log.disabled = True
        log.addFilter(block_filter)
        
    # Also clear loguru loggers if any
    try:
        from loguru import logger
        logger.remove()
    except ImportError:
        pass
    # dataflow.split_variables = no_op # Note: split_variables might be structurally necessary for some AST generation
    
    original_process = decompile.DvMethod.process
    
    def fast_process(self, doAST: bool = False):
        return original_process(self, doAST)
        
    decompile.DvMethod.process = fast_process

    # Hack: Fake Analysis to avoid slow initialization
    from androguard.core.analysis.analysis import MethodAnalysis
    class FakeAnalysis:
        def __init__(self, vm):
            self.methods = {}
            self.classes = {}
            self.vm = vm
            
        def get_method(self, method):
            if method not in self.methods:
                self.methods[method] = MethodAnalysis(self.vm, method)
            return self.methods[method]

    # androguard requires bytes or bytearray
    d = DEX(bytes(dex_bytes))
    dx = FakeAnalysis(d)
    
    target_class = d.get_class(dalvik_class_fmt)
    if not target_class:
        return f"Error: Class {dalvik_class_fmt} not found in the reconstructed DEX."
        
    c = decompile.DvClass(target_class, dx)
    c.process()
    # Remove the Decompile only time debug output
    return c.get_source()

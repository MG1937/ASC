import zipfile


def _quiet_loguru():
    try:
        from loguru import logger
        logger.remove()
    except Exception:
        pass
    try:
        import logging
        logging.getLogger("androguard").disabled = True
        logging.getLogger("androguard").setLevel(logging.CRITICAL)
    except Exception:
        pass


def get_manifest_xml(apk_path : str, pretty : bool = True) -> str:
    with zipfile.ZipFile(apk_path) as zf:
        manifest_data = zf.read("AndroidManifest.xml")

    _quiet_loguru()
    from androguard.core.axml import AXMLPrinter
    _quiet_loguru()

    axml = AXMLPrinter(manifest_data)
    if not axml.is_valid():
        raise ValueError("AndroidManifest.xml is not a valid binary XML")
    return axml.get_xml(pretty=pretty).decode("utf-8", errors="replace")

from dataclasses import dataclass


@dataclass(frozen=True)
class FindRefHit:
    dex_name: str
    caller_class: str
    caller_method: str
    matched: tuple


@dataclass(frozen=True)
class GetClassResult:
    dex_name: str
    class_name: str
    source: str


def format_findref_hit(hit: FindRefHit) -> str:
    matched = "; ".join(hit.matched)
    return (
        f"{hit.dex_name} | {hit.caller_class}->{hit.caller_method} "
        f"| matched=({matched})"
    )


def findref_hit_to_dict(hit: FindRefHit) -> dict:
    return {
        "dex_name": hit.dex_name,
        "caller_class": hit.caller_class,
        "caller_method": hit.caller_method,
        "matched": list(hit.matched),
    }


def getclass_result_to_dict(result: GetClassResult) -> dict:
    return {
        "dex_name": result.dex_name,
        "class_name": result.class_name,
        "source": result.source,
    }

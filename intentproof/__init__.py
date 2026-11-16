from pathlib import Path

_src_root = Path(__file__).resolve().parent / 'src' / 'intentproof'
if str(_src_root) not in __path__:
    __path__.append(str(_src_root))

from .engine import run_scenario

__all__ = ['run_scenario']

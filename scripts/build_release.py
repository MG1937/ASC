"""Build a source distribution from tracked runtime files."""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def build(version, output):
    if not re.fullmatch(r'v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:alpha|beta|rc)\.[1-9]\d*)?', version):
        raise ValueError('expected vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-rc.N (also alpha/beta)')
    paths = subprocess.check_output(
        ['git', 'ls-files', '-z', '--', 'main.py', 'requirements.txt', 'README.md', 'src', 'docs'],
        cwd=ROOT).decode().split('\0')
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f'ASC-{version}-source.zip'
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as package:
        for path in sorted(filter(None, paths)):
            info = zipfile.ZipInfo(f'ASC-{version}/{path}')
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            package.writestr(info, (ROOT / path).read_bytes())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output / 'SHA256SUMS').write_text(f'{digest}  {archive.name}\n', encoding='ascii')
    return archive


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('version')
    parser.add_argument('--output', type=Path, default=Path('dist'))
    args = parser.parse_args()
    print(build(args.version, args.output))

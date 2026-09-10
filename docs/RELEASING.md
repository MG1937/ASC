# Source releases

Python 3.11 or 3.12 is required. Extract `ASC-vX.Y.Z-source.zip`, enter the
extracted directory, and run:

```sh
python -m pip install -r requirements.txt
python main.py --help
python main.py getclass app.apk com.example.Main --debug
python main.py findrefs app.apk string token
python main.py app.apk --gui
```

The GUI additionally needs Tk (on Debian/Ubuntu: `python3-tk`). Dependencies
are installed separately; the archive is not a standalone executable.
`SHA256SUMS` verifies the downloaded ZIP; it does not change DEX signatures.

## Maintainers

Merge the PR into `dev-0.1.0` first, then tag the intended commit with
`vMAJOR.MINOR.PATCH` (or `-alpha.N`, `-beta.N`, `-rc.N`) and push that tag.
The Release workflow rejects tags outside the development branch and compares
performance against the tagged commit's first parent, by immutable SHA.
All unit/integration tests, paired performance checks, and absolute budgets
must pass on Python 3.11 and 3.12 before publication. A failed gate publishes
nothing. Prerelease tags create GitHub prereleases.

PR CI also builds the source package and tests its CLI after extraction outside
the checkout. Only tracked runtime files, requirements, README and docs enter
the deterministic ZIP; test DEX/APK fixtures and local scripts are excluded.

Local packaging: `python scripts/build_release.py v0.1.0 --output dist`.
The workflow creates a draft, uploads the ZIP and SHA256SUMS, then publishes it.
If upload fails, only a draft remains; rerunning replaces draft assets.
Published releases are never overwritten automatically.

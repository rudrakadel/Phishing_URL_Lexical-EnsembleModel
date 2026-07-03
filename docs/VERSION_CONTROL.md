# PhishScope Local Version Control

PhishScope now has two local rollback mechanisms.

## Git history

The project folder is a git repository. The first commit is the original baseline before launcher and health-check improvements:

```powershell
git log --oneline
```

To inspect changes:

```powershell
git status
git diff
```

## Startup restore snapshots

When you run `START_PHISHSCOPE.bat` or `setup_and_run.bat`, the launcher asks:

```text
C - Create restore snapshot, then start
S - Start without snapshot
R - Restore a previous snapshot
L - List snapshots
Q - Quit
```

Snapshots are copied into `.phishscope_versions`. They exclude machine-specific folders such as `.venv`, `.git`, runtime logs, screenshots, distributions, and legacy archives.

Use snapshots before making larger local changes. Use git when you need exact source-code history and diffs.

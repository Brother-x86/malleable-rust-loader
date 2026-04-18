import os
import re
import subprocess
import typer
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich import print as rprint

app = typer.Typer(
    name="obfstr-patch",
    help="🔒 Obfusque automatiquement les strings dans les fichiers Rust avec obfstr!",
    pretty_exceptions_show_locals=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)
console = Console()

SKIP_PATTERNS = [
    r'obfstr!',
    r'encrypt_string!',
    r'include_bytes!', 
    r'\bpub\b',
    r'\bfn\b',
    r'\bextern\b',
    r'^\s*use\s',
    r'^\s*#',
    r'^\s*//',
    r'^\s*\*',
    r'#\[',
    r'\bmod\b',
    r'impl\b',
]

STRING_REGEX = re.compile(r'"((?:[^"\\]|\\.)*)"')
OBFSTR_IMPORT = 'use obfstr::obfstr;\n'

FORMAT_MACROS_RE = re.compile(
    r'\b(format|write|writeln|print|println|eprint|eprintln|panic)\s*!'
)


def should_skip_line(line: str) -> bool:
    return any(re.search(pattern, line) for pattern in SKIP_PATTERNS)


def split_args(s: str) -> list:
    args = []
    depth = 0
    current = ''
    for char in s:
        if char in '([{':
            depth += 1
            current += char
        elif char in ')]}':
            depth -= 1
            current += char
        elif char == ',' and depth == 0:
            args.append(current)
            current = ''
        else:
            current += char
    if current.strip():
        args.append(current)
    return args


def transform_format_line(line: str) -> str:
    macro_match = FORMAT_MACROS_RE.search(line)
    if not macro_match:
        return line

    after_name = line[macro_match.end():]
    paren_match = re.match(r'\s*\(', after_name)
    if not paren_match:
        return line

    macro_content_start = macro_match.end() + paren_match.end()
    after_paren = line[macro_content_start:]

    writer_prefix = ''
    if macro_match.group(1) in ('write', 'writeln'):
        writer_match = re.match(r'([^,]+,\s*)', after_paren)
        if writer_match:
            writer_prefix = writer_match.group(1)
            after_paren = after_paren[writer_match.end():]

    str_match = re.match(r'"((?:[^"\\]|\\.)*)"', after_paren)
    if not str_match:
        return line

    fmt_content = str_match.group(1)
    after_str = after_paren[str_match.end():]

    parts = re.split(r'(\{[^{}]*\})', fmt_content)
    static_parts = parts[0::2]
    specifiers = parts[1::2]

    if not any(p for p in static_parts):
        return line

    new_fmt_parts = []
    for i, static in enumerate(static_parts):
        if static:
            new_fmt_parts.append('{}')
        if i < len(specifiers):
            new_fmt_parts.append(specifiers[i])
    new_fmt = ''.join(new_fmt_parts)

    original_args = []
    suffix = ''

    rest_stripped = after_str.lstrip()
    if rest_stripped.startswith(','):
        comma_pos = after_str.index(',')
        rest = after_str[comma_pos + 1:].lstrip()

        inner_depth = 0
        close_idx = len(rest)
        for idx, ch in enumerate(rest):
            if ch in '([{':
                inner_depth += 1
            elif ch in ')]}':
                if inner_depth == 0:
                    close_idx = idx
                    break
                inner_depth -= 1

        inner = rest[:close_idx]
        suffix = rest[close_idx:]
        original_args = [a for a in split_args(inner) if a.strip()]
    else:
        suffix = after_str.lstrip()

    all_args = []
    orig_idx = 0
    for i, static in enumerate(static_parts):
        if static:
            all_args.append(f'obfstr!("{static}")')
        if i < len(specifiers):
            if orig_idx < len(original_args):
                all_args.append(original_args[orig_idx].strip())
                orig_idx += 1

    all_args.extend(a.strip() for a in original_args[orig_idx:])

    prefix = line[:macro_content_start]
    args_joined = ', '.join(all_args)
    return f'{prefix}{writer_prefix}"{new_fmt}", {args_joined}{suffix}'


def process_line(line: str) -> str:
    if should_skip_line(line):
        return line

    if FORMAT_MACROS_RE.search(line):
        return transform_format_line(line)

    def replace_string(match):
        content = match.group(1)
        if content.strip() == '':
            return match.group(0)
        if '{' in content:
            return match.group(0)
        # Ignorer les patterns de match : "..." =>
        after = line[match.end():].lstrip()
        if after.startswith('=>'):
            return match.group(0)
        # Cote droit d'un match arm : => "..." → obfstr + to_string
        before = line[:match.start()]
        if '=>' in before:
            return f'obfstr!("{content}").to_string()'
        return f'obfstr!("{content}")'

    return STRING_REGEX.sub(replace_string, line)


def has_obfstr_import(lines: list) -> bool:
    return any('use obfstr::obfstr' in line for line in lines)


def insert_import(lines: list) -> list:
    last_use_end = -1
    brace_depth = 0
    i = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Mise à jour de la profondeur pour détecter si on est au niveau racine
        brace_depth += line.count('{') - line.count('}')

        # On ne considère que les `use` au niveau racine (brace_depth == 0)
        if brace_depth == 0 and re.match(r'^use\s', stripped):
            if stripped.endswith(';'):
                last_use_end = i
            else:
                # use multi-lignes avec accolades : on suit jusqu'à la fermeture
                depth = stripped.count('{') - stripped.count('}')
                j = i
                while depth > 0 and j < len(lines) - 1:
                    j += 1
                    depth += lines[j].count('{') - lines[j].count('}')
                last_use_end = j
                i = j

        i += 1

    if last_use_end >= 0:
        lines.insert(last_use_end + 1, OBFSTR_IMPORT)
    else:
        insert_at = 0
        for i, line in enumerate(lines):
            if line.startswith('#!'):
                insert_at = i + 1
            else:
                break
        lines.insert(insert_at, OBFSTR_IMPORT)

    return lines


def process_file(filepath: str, dry_run: bool = False) -> dict:
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    new_lines = []
    changed = False
    strings_replaced = 0
    diffs = []

    for i, line in enumerate(lines):
        new_line = process_line(line)
        if new_line != line:
            changed = True
            strings_replaced += 1
            diffs.append((i + 1, line.rstrip(), new_line.rstrip()))
        new_lines.append(new_line)

    import_added = False
    if changed and not has_obfstr_import(new_lines):
        new_lines = insert_import(new_lines)
        import_added = True

    if changed and not dry_run:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)

    return {
        "changed": changed,
        "import_added": import_added,
        "strings_replaced": strings_replaced,
        "diffs": diffs,
    }


@app.command()
def patch(
    path: Path = typer.Argument(..., help="Dossier ou fichier .rs a traiter"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n", help="Simule sans modifier les fichiers"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Affiche aussi les fichiers skippes"),
    diff: bool = typer.Option(False, "--diff", "-d", help="Affiche les lignes modifiees avant/apres"),
    exclude: Optional[str] = typer.Option(None, "--exclude", "-e", help="Dossier ou pattern a exclure (ex: 'examples' ou 'tests|examples')"),
    revert: bool = typer.Option(False, "--revert", "-r", help="Annule toutes les modifications non commitees via git restore"),
):
    """
    Patch tous les fichiers .rs pour obfusquer les strings avec obfstr!
    """
    if not path.exists():
        rprint(f"[red]Path introuvable: {path}[/red]")
        raise typer.Exit(1)

    project_root = str(path) if path.is_dir() else str(path.parent)

    if revert:
        console.rule("[bold red]Revert git...[/bold red]")
        git_root = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, cwd=project_root
        ).stdout.strip()
        result = subprocess.run(["git", "restore", str(path)], cwd=git_root)
        if result.returncode != 0:
            rprint("[yellow]git restore a echoue, essai avec git checkout...[/yellow]")
            subprocess.run(["git", "checkout", "--", str(path)], cwd=git_root)
        else:
            rprint("[green]Modifications annulees avec succes.[/green]")
        raise typer.Exit(0)
        
    if path.is_file() and path.suffix == '.rs':
        rs_files = [str(path)]
    else:
        rs_files = [
            os.path.join(dirpath, filename)
            for dirpath, _, filenames in os.walk(path)
            for filename in filenames
            if filename.endswith('.rs')
        ]

    if exclude:
        rs_files = [f for f in rs_files if not re.search(exclude, f)]

    if not rs_files:
        rprint("[yellow]Aucun fichier .rs trouve.[/yellow]")
        raise typer.Exit(0)

    console.rule(f"[bold blue]obfstr-patch {'(DRY RUN) ' if dry_run else ''}-- {len(rs_files)} fichiers[/bold blue]")

    stats = {"patched": 0, "skipped": 0, "imports": 0, "strings": 0}
    all_results = {}

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Fichier", style="dim", max_width=60)
    table.add_column("Status", justify="center")
    table.add_column("Strings", justify="right")
    table.add_column("Import", justify="center")

    for filepath in rs_files:
        result = process_file(filepath, dry_run=dry_run)
        all_results[filepath] = result
        short_path = os.path.relpath(filepath, str(path))

        if result["changed"]:
            stats["patched"] += 1
            stats["strings"] += result["strings_replaced"]
            if result["import_added"]:
                stats["imports"] += 1
            table.add_row(
                short_path,
                "[green]PATCHED[/green]" if not dry_run else "[yellow]DRY RUN[/yellow]",
                str(result["strings_replaced"]),
                "[green]✓[/green]" if result["import_added"] else "[dim]-[/dim]",
            )
        else:
            stats["skipped"] += 1
            if verbose:
                table.add_row(short_path, "[dim]SKIP[/dim]", "0", "[dim]-[/dim]")

    console.print(table)

    if diff:
        console.rule("[bold magenta]Diff des modifications[/bold magenta]")
        for filepath, result in all_results.items():
            if result["diffs"]:
                short_path = os.path.relpath(filepath, str(path))
                console.rule(f"[magenta]{short_path}[/magenta]")
                for lineno, before, after in result["diffs"]:
                    rprint(f"  [dim]L{lineno}[/dim]")
                    rprint(f"  [red]- {before}[/red]")
                    rprint(f"  [green]+ {after}[/green]")

    console.rule("[bold green]Resume[/bold green]")
    rprint(f"  [green]Patches  :[/green] {stats['patched']}")
    rprint(f"  [dim]Skippes  :[/dim] {stats['skipped']}")
    rprint(f"  [cyan]Imports  :[/cyan] {stats['imports']}")
    rprint(f"  [cyan]Strings  :[/cyan] {stats['strings']}")

    if dry_run:
        rprint("\n  [yellow]Mode DRY RUN -- aucun fichier modifie[/yellow]")


if __name__ == '__main__':
    app()
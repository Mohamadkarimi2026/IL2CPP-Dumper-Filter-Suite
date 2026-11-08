#beta version
import argparse
import glob
import io
import os
from collections import namedtuple
import re
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path


BANNER = r"""
======================================================
   IL2CPP Android Dumper & dnSpy Filter Suite
   Credit by Mohammad Karimi  |  T.me/mohka1994
======================================================
"""

SCRIPT_DIR = Path(__file__).resolve().parent
DUMPER_NAME = "Il2CppDumper-Python"
DUMPER_URL = "https://github.com/springmusk026/Il2CppDumper-Python.git"
MAGIC = bytes.fromhex("af1bb1fa")
MAX_ENTRY = 512 * 1024 * 1024

# Target Game Assemblies for Filtering
DEFAULT_GAME_ASSEMBLIES = [
    "ScriptsAssembly.dll",
    "LogicAssembly.dll",
    "Assembly-CSharp.dll",
    "UtilsScripts.dll",
    "Assembly-CSharp-firstpass.dll",
]

# Strict Types Allowed (Including float and double)
ALLOWED_TYPES = {
    "bool", "int", "SafeInt", "void",
    "float", "double", "Single", "Double", "SafeFloat"
}

DEFAULT_KEYWORDS = [
    "has_", "hasenough", "has_enough", "is_", "can_", "allow_",
    "vip", "premium", "pro", "purchase", "purchased", "buy",
    "coin", "gold", "diamond", "gem", "money", "cash", "wallet", "balance",
    "heart", "life", "energy", "stamina", "ammo", "health", "score", "star",
    "reward", "gift", "bonus", "chest", "box", "free", "unlock", "price",
    "sale", "paid", "pack", "bundle", "sub", "license", "ad_removed",
    "adremoved", "disable_ads", "full_version", "fullversion",
    "level", "rank", "tier", "speed", "power", "damage"
]

EXCLUDE_METHODS = {
    "gethashcode", "hashcode", "hasfocus", "haserror",
    "isdestroyed", "tostring", "equals", "gettype"
}

EXCLUDE_CLASS_PATTERNS = [
    "analytics", "tracker", "adjust", "appsflyer", "tenjin", 
    "crashlytics", "ironsource", "demo", "test", "example", 
    "guideline", "tutorial", "debug"
]

IMAGE_RE = re.compile(r"^//\s*Image\s+(\d+):\s*([^\s]+)\s*-\s*(\d+)")
CLASS_RE = re.compile(r"^(?:public|internal|private|protected)?\s*(?:static|sealed|abstract)?\s*(?:class|struct|interface)\s+([^\s:]+).*?//\s*TypeDefIndex:\s*(\d+)")
RVA_RE = re.compile(r"^//\s*RVA:\s*(0x[0-9a-fA-F]+)")


def status(message):
    print(message, flush=True)


def auto_detect_dump_file() -> Path | None:
    for name in ["dump.cs", "dump-(2).cs", "dump-2.cs"]:
        p = Path(name)
        if p.is_file():
            return p
    for f in Path(".").glob("dump*.cs"):
        if f.is_file():
            return f
    cs_files = list(Path(".").glob("*.cs"))
    if cs_files:
        return cs_files[0]
    return None


def metadata_version(data, total_size=None):
    total_size = len(data) if total_size is None else total_size
    if len(data) < 128 or data[:4] != MAGIC:
        return None

    version, first = struct.unpack_from("<II", data, 4)
    if not (
        16 <= version <= 128
        and 64 <= first <= min(4096, len(data), total_size)
        and first % 4 == 0
    ):
        return None

    count = min(24, (first - 8) // 8)
    if count < 8:
        return None

    populated = 0
    for i in range(count):
        off, size = struct.unpack_from("<II", data, 8 + 8 * i)
        if off == size == 0:
            continue
        if off < first or off > total_size or size > total_size - off:
            return None
        populated += bool(size)

    return version if populated >= 6 else None


def transform(data, key, op):
    if not key:
        raise ValueError("Empty recovery key.")

    if op == "xor":
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    if op == "add":
        return bytes((b + key[i % len(key)]) & 255 for i, b in enumerate(data))
    if op == "sub":
        return bytes((b - key[i % len(key)]) & 255 for i, b in enumerate(data))

    raise ValueError(f"Unknown transform: {op}")


def recover(blob, library):
    skips = [0]
    if len(blob) >= 4 and any(
        int.from_bytes(blob[:4], endian) == len(blob) - 4
        for endian in ("big", "little")
    ):
        skips.append(4)

    for skip in skips:
        payload = blob[skip:]
        ver = metadata_version(payload)

        if ver is not None:
            return payload, {
                "mode": "plaintext",
                "header_bytes": skip,
                "version": ver,
            }

        if len(payload) < 128:
            continue

        sample = payload[:4096]

        for op in ("xor", "add", "sub"):
            if op == "xor":
                prefix = bytes(sample[i] ^ MAGIC[i] for i in range(4))
            elif op == "add":
                prefix = bytes((MAGIC[i] - sample[i]) & 255 for i in range(4))
            else:
                prefix = bytes((sample[i] - MAGIC[i]) & 255 for i in range(4))

            pos = library.find(prefix)

            while pos >= 0:
                for n in range(4, min(65, len(library) - pos + 1)):
                    key = library[pos:pos + n]

                    if metadata_version(
                        transform(sample, key, op), len(payload)
                    ) is None:
                        continue

                    plain = transform(payload, key, op)
                    ver = metadata_version(plain)

                    if ver is not None:
                        return plain, {
                            "mode": op,
                            "key_offset": pos,
                            "key_hex": key.hex(),
                            "header_bytes": skip,
                            "version": ver,
                        }

                pos = library.find(prefix, pos + 1)

    return None, None


def prompt_path(text, base_dir=None):
    value = input(text + "\n> ").strip().strip('"').strip("'")
    if not value:
        raise ValueError("A path is required.")

    path = Path(value).expanduser()
    if base_dir is not None and not path.is_absolute():
        path = base_dir / path

    path = path.resolve()
    if not path.is_file():
        raise ValueError(f"File not found: {path}")

    return path


def prompt_apk_path():
    while True:
        try:
            path = prompt_path("Enter APK path", base_dir=SCRIPT_DIR)
            if path.suffix.lower() not in (".apk", ".apks", ".apkm", ".xapk", ".zip"):
                raise ValueError(f"Not a supported APK/ZIP file: {path}")
            if not zipfile.is_zipfile(path):
                raise ValueError(f"Not a valid APK/ZIP file: {path}")
            return path
        except ValueError as exc:
            status(f"Invalid APK: {exc}")


def select_apk():
    apk_files = sorted(
        (
            Path(name) for pattern in ("*.apk", "*.apks", "*.apkm", "*.xapk", "*.zip")
            for name in glob.glob(str(SCRIPT_DIR / pattern))
            if Path(name).is_file()
        ),
        key=lambda path: path.name.lower(),
    )

    if not apk_files:
        status("No APK/ZIP files found beside the script.")
        return prompt_apk_path()

    status("APK/ZIP files found beside the script:")
    for i, path in enumerate(apk_files, 1):
        status(f"  {i}) {path.name}")

    manual_option = len(apk_files) + 1
    status(f"  {manual_option}) Enter an APK path manually")

    while True:
        choice = input(f"Choose 1-{manual_option} [1]: ").strip() or "1"
        if not choice.isdigit():
            status("Choose a listed number.")
            continue

        number = int(choice)
        if 1 <= number <= len(apk_files):
            return apk_files[number - 1].resolve()
        if number == manual_option:
            return prompt_apk_path()

        status("Choose a listed number.")


def choose(items, title):
    if len(items) == 1:
        return items[0]

    status(title)
    for i, item in enumerate(items, 1):
        label = item.filename if hasattr(item, "filename") else str(item)
        status(f"  {i}. {label}")

    while True:
        raw = input(f"Choose 1-{len(items)}: ").strip()
        try:
            number = int(raw)
            if 1 <= number <= len(items):
                return items[number - 1]
        except ValueError:
            pass
        status("Choose a listed number.")


def get_apk_inputs(apk_path, interactive):
    status(f"Opening APK/ZIP: {apk_path}")
    ArchiveEntry = namedtuple("ArchiveEntry", "filename file_size data")

    def entries(source, label, depth=0):
        if depth > 4:
            return []
        found = []
        with zipfile.ZipFile(source) as zf:
            for item in zf.infolist():
                if item.is_dir() or item.file_size > MAX_ENTRY:
                    continue
                name = f"{label}!/{item.filename}" if label else item.filename
                lower = item.filename.lower()
                basename = Path(lower).name
                if basename == "libil2cpp.so" or basename in ("global-metadata.dat", "sysinfo.dat"):
                    found.append(ArchiveEntry(name, item.file_size, zf.read(item)))
                elif lower.endswith((".apk", ".zip", ".apks", ".apkm", ".xapk")):
                    data = zf.read(item)
                    if zipfile.is_zipfile(io.BytesIO(data)):
                        found.extend(entries(io.BytesIO(data), name, depth + 1))
        return found

    files = entries(apk_path, str(apk_path))
    libs = [item for item in files if Path(item[0].lower()).name == "libil2cpp.so"]
    metas = [item for item in files if Path(item[0].lower()).name in ("global-metadata.dat", "sysinfo.dat")]

    if not libs:
        raise ValueError("Archive contains no libil2cpp.so.")
    if not metas:
        raise ValueError("No global-metadata.dat/sysinfo.dat found in archive.")

    libs.sort(key=lambda item: ("arm64-v8a" not in item[0].lower(), item[0].lower()))
    metas.sort(key=lambda item: ("global-metadata.dat" not in item[0].lower(), item[0].lower()))

    if (len(libs) > 1 or len(metas) > 1) and not interactive:
        raise ValueError("Archive contains multiple candidates. Run interactively.")

    lib_item = choose(libs, "Libraries found:") if interactive else libs[0]
    meta_item = choose(metas, "Metadata candidates:") if interactive else metas[0]

    status(f"Reading library: {lib_item[0]}")
    libbytes = lib_item[2]
    status(f"Reading metadata: {meta_item[0]}")
    blob = meta_item[2]

    return libbytes, blob, lib_item[0]


def is_valid_dumper(path):
    return (
        path.is_dir()
        and (path / "il2cpp_dumper_py" / "__main__.py").is_file()
    )


def ask_yes_no(question, default=False):
    hint = "[Y/n]" if default else "[y/N]"
    while True:
        answer = input(f"{question} {hint}: ").strip().lower()
        if not answer:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        status("Please enter y or n.")


def custom_dumper_path():
    while True:
        raw = input("Enter custom parent directory or repository directory:\n> ").strip().strip('"').strip("'")
        if not raw:
            status("A directory path is required.")
            continue

        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = SCRIPT_DIR / path
        path = path.resolve()

        if path.exists() and not path.is_dir():
            status(f"Not a directory: {path}")
            continue

        if path.name.lower() == DUMPER_NAME.lower():
            return path
        return path / DUMPER_NAME


def choose_dumper_location():
    home_target = Path.home() / DUMPER_NAME
    script_target = SCRIPT_DIR / DUMPER_NAME

    def state(path):
        return "installed" if is_valid_dumper(path) else "not installed"

    status("\nWhere should Il2CppDumper-Python be used or downloaded?")
    status(f"  1) Termux home [{state(home_target)}]: {home_target}")
    status(f"  2) Beside this script [{state(script_target)}]: {script_target}")
    status("  3) Custom directory")
    while True:
        choice = input("Choose 1-3 [1]: ").strip() or "1"
        if choice == "1":
            return home_target
        if choice == "2":
            return script_target
        if choice == "3":
            return custom_dumper_path()
        status("Choose 1, 2, or 3.")


def locate_dumper(explicit_dir=None, explicit_script=None, clone=True, interactive=False, auto_yes=False):
    if explicit_script:
        path = Path(explicit_script).expanduser().resolve()
        if not path.is_file():
            raise ValueError(f"Dumper script not found: {path}")
        return path

    target = Path(explicit_dir).expanduser().resolve() if explicit_dir else (choose_dumper_location() if interactive else Path.home() / DUMPER_NAME)

    if is_valid_dumper(target):
        status(f"Il2CppDumper-Python is already installed: {target}")
        return target.resolve()

    if target.exists():
        raise ValueError(f"Dumper directory exists but is incomplete: {target}")

    if not clone:
        return None

    if interactive:
        if not ask_yes_no("Do you want to download it now?", default=False):
            return None
    elif not auto_yes:
        return None

    git = shutil.which("git")
    if not git:
        raise ValueError("git is unavailable; install it with 'pkg install git'.")

    target.parent.mkdir(parents=True, exist_ok=True)
    status(f"Downloading Il2CppDumper-Python into: {target}")

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    proc = subprocess.run([git, "clone", "--progress", DUMPER_URL, str(target)], env=env, check=False)

    if proc.returncode != 0 or not is_valid_dumper(target):
        raise ValueError(f"Download failed: {target}")

    return target.resolve()


# --- Filtering & dnSpy formatting functions ---

def read_images(input_path: Path):
    starts = []
    names = []
    with input_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line_s = line.strip()
            if not line_s.startswith("// Image"):
                if line_s and not line_s.startswith("//"):
                    break
                continue
            m = IMAGE_RE.match(line_s)
            if m:
                names.append(m.group(2))
                starts.append(int(m.group(3)))
    return starts, names


def get_assembly_name(type_def_index: int, starts: list, names: list):
    idx = -1
    for i, s in enumerate(starts):
        if s <= type_def_index:
            idx = i
        else:
            break
    if 0 <= idx < len(names):
        return names[idx]
    return None


def is_valid_method(sig: str, name: str, keywords: list) -> bool:
    if "string" in sig.lower():
        return False
    name_lower = name.lower()
    if name_lower in EXCLUDE_METHODS:
        return False
    if not any(k in name_lower for k in keywords):
        return False

    sig_before_name = sig.split(name)[0].strip()
    tokens = sig_before_name.split()
    if not tokens:
        return False
    return tokens[-1] in ALLOWED_TYPES


def parse_dump(input_path: Path, output_path: Path, target_assemblies: set, keywords: list):
    if not input_path.is_file():
        print(f"\n\033[91m[-] Error: Input file not found -> {input_path}\033[0m")
        return False

    starts, image_names = read_images(input_path)
    if not starts:
        print(f"\n\033[91m[-] Error: Could not read Image headers from {input_path}\033[0m")
        return False

    print(f"\n\033[94m[*] Processing: {input_path.name} -> {output_path.name}\033[0m")

    asm_data = {asm: [] for asm in target_assemblies}
    curr_namespace = "// Namespace: GlobalNamespace"
    curr_class = None
    curr_asm = None
    curr_methods = []
    pending_rva = None

    with input_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line_s = line.strip()
            if line_s.startswith("// Namespace:"):
                ns_val = line_s.split(":", 1)[1].strip()
                curr_namespace = f"// Namespace: {ns_val if ns_val else 'GlobalNamespace'}"
                continue

            cm = CLASS_RE.match(line_s)
            if cm:
                if curr_asm and curr_class and curr_methods:
                    asm_data[curr_asm].append((curr_namespace, curr_class, curr_methods))

                cname = cm.group(1)
                tdef = int(cm.group(2))
                curr_asm = get_assembly_name(tdef, starts, image_names)
                curr_methods = []
                pending_rva = None

                cname_lower = cname.lower()
                if curr_asm not in target_assemblies or any(p in cname_lower for p in EXCLUDE_CLASS_PATTERNS):
                    curr_asm = None
                    curr_class = None
                else:
                    curr_class = line_s
                continue

            if not curr_asm:
                continue

            rm = RVA_RE.match(line_s)
            if rm:
                pending_rva = line_s
                continue

            if pending_rva and line_s.endswith("{ }"):
                sig = line_s[:-3].strip()
                if "(" in sig:
                    name_part = sig.split("(")[0].strip().split()[-1]
                    if "." in name_part:
                        name_part = name_part.split(".")[-1]
                    if is_valid_method(sig, name_part, keywords):
                        curr_methods.append((pending_rva, sig))
                pending_rva = None

        if curr_asm and curr_class and curr_methods:
            asm_data[curr_asm].append((curr_namespace, curr_class, curr_methods))

    total_methods = 0
    total_classes = 0
    with output_path.open("w", encoding="utf-8") as out:
        for asm in sorted(asm_data.keys()):
            classes = asm_data[asm]
            if not classes:
                continue
            out.write("========================================\n")
            out.write(f"=== {asm} ===\n")
            out.write("========================================\n\n")

            for ns, cls_decl, methods in classes:
                total_classes += 1
                total_methods += len(methods)
                out.write(f"{ns}\n")
                out.write(f"{cls_decl}\n{{\n\t// Methods\n\n")

                for idx, (rva_str, m_sig) in enumerate(methods):
                    out.write(f"\t{m_sig} {{ }}\n")
                    out.write(f"\t{rva_str}\n")
                    if idx < len(methods) - 1:
                        out.write("\n")

                out.write("}\n\n\n")

    print(f"\033[92m[+] Success! Kept {total_classes} classes and {total_methods} methods.\033[0m")
    print(f"\033[92m[+] Output file: {output_path.resolve()}\033[0m")
    return True


def manage_assemblies_menu(assemblies: set, input_file: Path | None):
    while True:
        asm_list = sorted(list(assemblies))
        print("\n" + "-" * 50)
        print("         MANAGE TARGET ASSEMBLIES (DLLs)")
        print("-" * 50)
        if not asm_list:
            print("  \033[91m(No assemblies selected!)\033[0m")
        else:
            for i, a in enumerate(asm_list, 1):
                print(f"  [{i:2d}] {a}")

        print("\nOptions:")
        print("  [+] Enter new DLL name(s) separated by comma/space to ADD")
        print("  [-] Enter '-number(s)' to REMOVE (e.g. -1 -2)")
        print("  [c] CLEAR all  |  [r] RESET default")
        if input_file and input_file.is_file():
            print("  [d] DETECT & SELECT from dump headers")
        print("  [0] Back to Menu")
        print("-" * 50)

        user_input = input("Choice / Action: ").strip()
        if user_input == "0" or user_input == "":
            break
        if user_input.lower() == "c":
            assemblies.clear()
            continue
        if user_input.lower() == "r":
            assemblies.clear()
            assemblies.update(DEFAULT_GAME_ASSEMBLIES)
            continue
        if user_input.lower() == "d" and input_file and input_file.is_file():
            _, available = read_images(input_file)
            for idx, name in enumerate(available, 1):
                status(f"  [{idx}] {name}")
            sel = input("Enter numbers to toggle: ").replace(",", " ").split()
            for s in sel:
                if s.isdigit() and 1 <= int(s) <= len(available):
                    p = available[int(s) - 1]
                    if p in assemblies:
                        assemblies.remove(p)
                    else:
                        assemblies.add(p)
            continue
        if user_input.startswith("-"):
            for num in user_input.replace("-", " ").replace(",", " ").split():
                if num.isdigit() and 1 <= int(num) <= len(asm_list):
                    assemblies.discard(asm_list[int(num) - 1])
            continue

        for t in user_input.replace(",", " ").split():
            if t:
                if not t.lower().endswith(".dll"):
                    t += ".dll"
                assemblies.add(t)


def run_filter_menu(dumpcs_path: Path | None = None):
    input_file = dumpcs_path or auto_detect_dump_file()
    output_file = Path("filtered_dnspy_dump.txt")
    assemblies = set(DEFAULT_GAME_ASSEMBLIES)
    keywords = list(DEFAULT_KEYWORDS)

    while True:
        print("\n" + "=" * 50)
        print("  IL2CPP Dump Filter - Credit by Mohammad Karimi")
        print("=" * 50)
        print(f" 1) Input Dump File  : \033[93m{input_file.name if input_file else 'NOT SELECTED'}\033[0m")
        print(f" 2) Output File      : \033[93m{output_file.name}\033[0m")
        print(f" 3) Manage DLLs      : \033[93m{len(assemblies)} target DLLs active\033[0m")
        print(f" 4) Keywords Count   : \033[93m{len(keywords)} active keywords\033[0m")
        print(f" 5) Add Custom Keyword / Prefix")
        print("-" * 50)
        print(" 6) \033[92mStart Filtering Process\033[0m")
        print(" 0) Exit / Back")
        print("=" * 50)

        choice = input("Enter option [0-6]: ").strip()
        if choice == "0":
            break
        elif choice == "1":
            p = input("Enter custom dump path: ").strip()
            if p and Path(p).is_file():
                input_file = Path(p)
        elif choice == "2":
            o = input("Enter output filename: ").strip()
            if o:
                output_file = Path(o)
        elif choice == "3":
            manage_assemblies_menu(assemblies, input_file)
        elif choice == "4":
            print(", ".join(sorted(keywords)))
        elif choice == "5":
            new_kw = input("Enter keyword: ").strip().lower()
            if new_kw and new_kw not in keywords:
                keywords.append(new_kw)
        elif choice == "6":
            if input_file and input_file.is_file():
                parse_dump(input_file, output_file, assemblies, keywords)
                break
            else:
                print("\033[91mInvalid dump file!\033[0m")


def main(argv=None):
    status(BANNER)
    ap = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""\
======================================================
   IL2CPP Android Dumper & dnSpy Filter Tool
   Credit by Mohammad Karimi  |  T.me/mohka1994
======================================================
Can run dump extraction, direct dump filtering, or both.
"""
    )
    # Recovery / Dumper Arguments
    ap.add_argument("--apk", help="APK containing library and metadata")
    ap.add_argument("--lib", help="extracted libil2cpp.so")
    ap.add_argument("--metadata", help="extracted metadata file")
    ap.add_argument("--out", help="output folder for dumper (default: ./il2cpp_result)")
    ap.add_argument("--dumper-dir", help="exact repository directory")
    ap.add_argument("--dumper-script", help="explicit dumper script path")
    ap.add_argument("--no-clone", action="store_true", help="do not download the dumper")
    ap.add_argument("--no-dump", action="store_true", help="recover metadata only")
    ap.add_argument("--yes", action="store_true", help="allow download non-interactive")

    # Filter CLI Arguments
    ap.add_argument("-f", "--filter", action="store_true", help="Run dump filtering (can run after dump or standalone)")
    ap.add_argument("-fm", "--filter-menu", action="store_true", help="Open the interactive filter menu directly")
    ap.add_argument("-fi", "--filter-input", help="Path to input dump.cs for filtering")
    ap.add_argument("-fo", "--filter-out", default="filtered_dnspy_dump.txt", help="Path to filtered output file")
    ap.add_argument("-k", "--keywords", nargs="+", help="Additional custom keywords for filtering")
    ap.add_argument("-a", "--assemblies", nargs="+", help="Specific target DLL assemblies for filtering")

    args = ap.parse_args(argv)

    # 1. Direct Filter Menu flag
    if args.filter_menu:
        target_f = Path(args.filter_input).resolve() if args.filter_input else None
        run_filter_menu(target_f)
        return 0

    # 2. Standalone CLI filter execution (no APK or Lib provided)
    if args.filter and not args.apk and not args.lib and sys.stdin.isatty() is False:
        input_dump = Path(args.filter_input) if args.filter_input else auto_detect_dump_file()
        if not input_dump or not input_dump.is_file():
            print("\033[91m[-] Error: Valid dump.cs file not found for filtering.\033[0m", file=sys.stderr)
            return 1

        target_assemblies = set(args.assemblies) if args.assemblies else set(DEFAULT_GAME_ASSEMBLIES)
        keywords = list(DEFAULT_KEYWORDS)
        if args.keywords:
            for kw in args.keywords:
                kw_c = kw.strip().lower()
                if kw_c and kw_c not in keywords:
                    keywords.append(kw_c)

        parse_dump(input_dump, Path(args.filter_out), target_assemblies, keywords)
        return 0

    try:
        interactive = sys.stdin.isatty()
        if not args.apk and not args.lib:
            if not interactive:
                # If only CLI filter is requested without dump params
                if args.filter:
                    input_dump = Path(args.filter_input) if args.filter_input else auto_detect_dump_file()
                    if input_dump and input_dump.is_file():
                        target_assemblies = set(args.assemblies) if args.assemblies else set(DEFAULT_GAME_ASSEMBLIES)
                        keywords = list(DEFAULT_KEYWORDS)
                        if args.keywords:
                            for kw in args.keywords:
                                kw_c = kw.strip().lower()
                                if kw_c and kw_c not in keywords:
                                    keywords.append(kw_c)
                        parse_dump(input_dump, Path(args.filter_out), target_assemblies, keywords)
                        return 0
                raise ValueError("Non-interactive run needs --apk or --lib/--metadata (or --filter-menu / -f).")
            args.apk = str(select_apk())

        out = Path(args.out or "./il2cpp_result").expanduser().resolve()
        out.mkdir(parents=True, exist_ok=True)

        if args.apk:
            apk = Path(args.apk).expanduser().resolve()
            libbytes, blob, libname = get_apk_inputs(apk, interactive)
        else:
            lp = Path(args.lib).expanduser().resolve()
            mp = Path(args.metadata).expanduser().resolve()
            libbytes = lp.read_bytes()
            blob = mp.read_bytes()
            libname = lp.name

        if not libbytes.startswith(b"\x7fELF"):
            raise ValueError("Selected library does not have a valid ELF header.")

        plain, details = recover(blob, libbytes)
        if plain is None:
            raise ValueError("Metadata recovery failed.")

        libout = out / Path(libname).name
        metaout = out / "global-metadata.dat"

        libout.write_bytes(libbytes)
        metaout.write_bytes(plain)

        if args.no_dump:
            status("Dump skipped by --no-dump.")
            return 0

        dumper = locate_dumper(
            explicit_dir=args.dumper_dir,
            explicit_script=args.dumper_script,
            clone=not args.no_clone,
            interactive=interactive,
            auto_yes=args.yes,
        )

        if dumper is None:
            return 0

        dumpdir = out / "dump"
        dumpdir.mkdir(parents=True, exist_ok=True)

        if dumper.is_file():
            cmd = [sys.executable, str(dumper), str(libout), str(metaout), str(dumpdir)]
            working_dir = dumper.parent
        else:
            cmd = [sys.executable, "-m", "il2cpp_dumper_py", str(libout), str(metaout), str(dumpdir)]
            working_dir = dumper

        proc = subprocess.run(cmd, check=False, cwd=str(working_dir))

        candidates = [dumpdir / "dump.cs", out / "dump.cs"]
        dumpcs = next((p for p in candidates if p.is_file() and p.stat().st_size > 0), None)

        if proc.returncode != 0:
            raise ValueError(f"Dumper failed with exit code {proc.returncode}.")
        if dumpcs is None:
            raise ValueError("Dumper succeeded but no dump.cs found.")

        status(f"\n[+] DUMP SUCCESS: {dumpcs}")

        # Post-dump execution logic
        if args.filter:
            # Automatic CLI filter after dump
            target_assemblies = set(args.assemblies) if args.assemblies else set(DEFAULT_GAME_ASSEMBLIES)
            keywords = list(DEFAULT_KEYWORDS)
            if args.keywords:
                for kw in args.keywords:
                    kw_c = kw.strip().lower()
                    if kw_c and kw_c not in keywords:
                        keywords.append(kw_c)
            parse_dump(dumpcs, Path(args.filter_out), target_assemblies, keywords)
        elif interactive:
            print("\n" + "=" * 50)
            if ask_yes_no("Do you want to filter the generated dump file now?", default=True):
                run_filter_menu(dumpcs)

        return 0

    except (OSError, ValueError, zipfile.BadZipFile, struct.error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    sys.exit(main())
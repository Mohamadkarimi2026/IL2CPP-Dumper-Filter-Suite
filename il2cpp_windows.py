#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Il2Cpp Windows metadata recovery and Android-style dump filtering.
Credit by Mohammad Karimi | T.me/mohka1994
Python 3.8+; no third-party Python dependencies.
"""
import argparse
import io
import os
import re
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if os.name == "nt":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # Keep the classic Windows console in its normal windowed state.
        kernel32.GetConsoleWindow.restype = ctypes.c_void_p
        user32 = ctypes.windll.user32
        user32.IsZoomed.argtypes = [ctypes.c_void_p]
        user32.ShowWindow.argtypes = [ctypes.c_void_p, ctypes.c_int]
        user32.SetWindowPos.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
            ctypes.c_int, ctypes.c_int, ctypes.c_uint,
        ]
        user32.GetWindowLongW.argtypes = [ctypes.c_void_p, ctypes.c_int]
        user32.GetWindowLongW.restype = ctypes.c_long
        user32.SetWindowLongW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_long]
        user32.SetWindowLongW.restype = ctypes.c_long
        console_window = kernel32.GetConsoleWindow()
        if console_window:
            if user32.IsZoomed(console_window):
                user32.ShowWindow(console_window, 9)  # SW_RESTORE
            # Keep the compact layout stable: permit minimizing, but prevent
            # resizing/maximizing from reflowing the ASCII header and menus.
            style = user32.GetWindowLongW(console_window, -16)  # GWL_STYLE
            style &= ~(0x00040000 | 0x00010000)  # THICKFRAME | MAXIMIZEBOX
            user32.SetWindowLongW(console_window, -16, style)
            user32.SetWindowPos(console_window, None, 0, 0, 570, 440, 0x0026)
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_ulong()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 4)
    except Exception:
        pass
USE_COLOR = sys.stdout.isatty()
CYAN, GREEN, YELLOW, RED, BOLD, RESET = (
    ("\033[96m", "\033[92m", "\033[93m", "\033[91m", "\033[1m", "\033[0m")
    if USE_COLOR else ("", "", "", "", "", "")
)
MAGIC = b'\xaf\x1b\xb1\xfa'
OPS = ('sub', 'add', 'xor')

DEFAULT_GAME_ASSEMBLIES = [
    "ScriptsAssembly.dll",
    "LogicAssembly.dll",
    "Assembly-CSharp.dll",
    "UtilsScripts.dll",
    "Assembly-CSharp-firstpass.dll",
]


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


def metadata_version(data,total=None):
    total=total or len(data)
    if len(data)<128 or data[:4]!=MAGIC: return None
    ver,first=struct.unpack_from('<II',data,4)
    if not 16<=ver<=128 or not 64<=first<=min(4096,len(data),total) or first%4: return None
    n=min(24,(first-8)//8); valid=0
    for i in range(n):
        off,size=struct.unpack_from('<II',data,8+i*8)
        if off==size==0: continue
        if off<first or off>total or size>total-off: return None
        if size: valid+=1
    return ver if valid>=6 else None


def transform(data,key,op):
    if not key: raise ValueError('Empty key')
    if op=='sub': return bytes((b-key[i%len(key)])&255 for i,b in enumerate(data))
    if op=='add': return bytes((b+key[i%len(key)])&255 for i,b in enumerate(data))
    return bytes(b^key[i%len(key)] for i,b in enumerate(data))


def candidate_keys(lib,prefix):
    pos=lib.find(prefix)
    while pos>=0:
        for n in range(4,min(33,len(lib)-pos+1)):
            yield pos,lib[pos:pos+n]
        pos=lib.find(prefix,pos+1)


def recover(blob,lib):
    # Recognize common 4-byte size prefixes in either endian, plus raw metadata.
    skips=[0]
    if len(blob)>=4:
        for endian in ('big','little'):
            if int.from_bytes(blob[:4],endian)==len(blob)-4: skips.append(4)
    for skip in dict.fromkeys(skips):
        payload=blob[skip:]
        if len(payload)<128: continue
        ver=metadata_version(payload[:4096],len(payload))
        if ver is not None: return payload,dict(operation='already_plain',header_bytes=skip,version=ver,key_offset=None)
        sample=payload[:4096]
        for op in OPS:
            if op=='sub': prefix=bytes((sample[i]-MAGIC[i])&255 for i in range(4))
            elif op=='add': prefix=bytes((MAGIC[i]-sample[i])&255 for i in range(4))
            else: prefix=bytes(sample[i]^MAGIC[i] for i in range(4))
            for off,key in candidate_keys(lib,prefix):
                plain_sample=transform(sample,key,op); ver=metadata_version(plain_sample,len(payload))
                if ver is None: continue
                plain=transform(payload,key,op)
                if metadata_version(plain[:4096],len(plain))==ver:
                    return plain,dict(operation=op,header_bytes=skip,version=ver,key_offset=off,key_hex=key.hex())
    return None,None


def apk_inputs(apk,out):
    def entries(source, label, depth=0):
        if depth > 4: return []
        found=[]
        with zipfile.ZipFile(source) as z:
            for item in z.infolist():
                if item.is_dir(): continue
                name=f'{label}!/{item.filename}' if label else item.filename
                lower=item.filename.lower()
                if lower.endswith(('/libil2cpp.so','libil2cpp.so')) or Path(lower).name == 'global-metadata.dat' or lower.endswith(('.dat','.bytes')):
                    found.append((name,item.file_size,z.read(item)))
                elif lower.endswith(('.apk','.zip','.apks','.apkm','.xapk')) and item.file_size <= 1024*1024*1024:
                    data=z.read(item)
                    if zipfile.is_zipfile(io.BytesIO(data)):
                        found.extend(entries(io.BytesIO(data),name,depth+1))
        return found
    files=entries(apk,str(apk))
    libs=[x for x in files if x[0].lower().endswith('/libil2cpp.so')]
    if not libs: raise ValueError('Archive contains no libil2cpp.so')
    libs.sort(key=lambda x:('arm64-v8a' not in x[0].lower(),x[0]))
    print('Libraries:')
    for i,x in enumerate(libs,1): print(f' {i}. {x[0]}')
    ix=int(input(f'Choose library [1-{len(libs)}] (default 1): ').strip() or '1')
    libpath=out/'libil2cpp.so'; libpath.write_bytes(libs[ix-1][2])
    candidates=[x for x in files if 4096<=x[1]<=256*1024*1024 and ('metadata' in x[0].lower() or x[0].lower().endswith(('.dat','.bytes')))]
    if not candidates: raise ValueError('No plausible metadata files found in archive; provide extracted metadata manually')
    candidates.sort(key=lambda x:('global-metadata.dat' not in x[0].lower(),-x[1]))
    print('Metadata candidates:')
    for i,x in enumerate(candidates[:30],1): print(f' {i}. {x[0]} ({x[1]:,} bytes)')
    ix=int(input(f'Choose metadata [1-{min(30,len(candidates))}] (default 1): ').strip() or '1')
    metapath=out/'metadata_input.bin'; metapath.write_bytes(candidates[ix-1][2])
    return libpath,metapath


def process(libpath,metapath,out):
    out.mkdir(parents=True,exist_ok=True); libpath=Path(libpath); metapath=Path(metapath)
    lib=libpath.read_bytes(); blob=metapath.read_bytes()
    if not lib.startswith(b'\x7fELF'): raise ValueError('libil2cpp input is not an ELF file')
    plain,info=recover(blob,lib)
    if plain is None: raise ValueError('Could not decrypt/validate metadata. This scanner supports common repeating sub/add/xor keys discoverable as byte sequences in the library; custom algorithms need a known key/transform.')
    meta=out/'global-metadata.dat'; meta.write_bytes(plain)
    print(f"Recovered metadata v{info['version']} using {info['operation']}; saved: {meta}")
    return meta,info


def auto_detect_dump_file():
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
    input_path, output_path = Path(input_path), Path(output_path)
    target_assemblies = {a.lower() for a in target_assemblies}
    keywords = [k.lower() for k in keywords if k.strip()]
    if input_path.resolve() == output_path.resolve():
        raise ValueError("Input and output must be different files.")
    if not input_path.is_file():
        print(f"\n{RED}[-] Error: Input file not found -> {input_path}{RESET}")
        return False

    starts, image_names = read_images(input_path)
    if not starts:
        print(f"\n{RED}[-] Error: Could not read Image headers from {input_path}{RESET}")
        return False

    print(f"\n{CYAN}[*] Processing: {input_path.name} -> {output_path.name}{RESET}")

    asm_data = {asm: [] for asm in image_names if asm.lower() in target_assemblies}
    class_namespace = "// Namespace: GlobalNamespace"
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
                    asm_data[curr_asm].append((class_namespace, curr_class, curr_methods))

                cname = cm.group(1)
                tdef = int(cm.group(2))
                curr_asm = get_assembly_name(tdef, starts, image_names)
                curr_methods = []
                pending_rva = None

                cname_lower = cname.lower()
                if curr_asm is None or curr_asm.lower() not in target_assemblies or any(p in cname_lower for p in EXCLUDE_CLASS_PATTERNS):
                    curr_asm = None
                    curr_class = None
                else:
                    curr_class = line_s
                    class_namespace = curr_namespace
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
            asm_data[curr_asm].append((class_namespace, curr_class, curr_methods))

    total_methods = 0
    total_classes = 0
    output_path.parent.mkdir(parents=True, exist_ok=True)
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

    print(f"{GREEN}[+] Success! Kept {total_classes} classes and {total_methods} methods.{RESET}")
    print(f"{GREEN}[+] Output file: {output_path.resolve()}{RESET}")
    return True


def print_banner():
    print(f"{CYAN}{BOLD}")
    print(r"      ___ _    ____   ____ ____  ____  ")
    print(r"     |_ _| |  |___ \ / ___|  _ \|  _ \ ")
    print(r"      | || |    __) | |   | |_) | |_) |")
    print(r"      | || |__ / __/| |___|  __/|  __/ ")
    print(r"     |___|____|_____|\____|_|   |_|    ")
    print(f"{RESET}")
    print(f"{GREEN}==================================================================={RESET}")
    print(f" {BOLD}IL2CPP Windows Dumper & Filter Suite{RESET}")
    print(f" Credit by {YELLOW}Mohammad Karimi{RESET}  |  {CYAN}T.me/mohka1994{RESET}")
    print(f"{GREEN}==================================================================={RESET}")


def screen():
    # Redraw the fixed header after clearing, so it remains on every screen.
    if sys.stdout.isatty():
        if os.name == 'nt':
            os.system('cls')
        else:
            print('\033[2J\033[H', end='')
    print_banner()


def pause():
    input(f"\n{YELLOW}Press Enter to return...{RESET}")


def path_value(value):
    return Path(value.strip().strip('"').strip("'")).expanduser().resolve()


def ask_file(prompt):
    while True:
        raw = input(f"{YELLOW}{prompt} (0 = Back): {RESET}").strip()
        if raw == '0':
            return None
        if raw:
            path = path_value(raw)
            if path.is_file():
                return path
        print(f"{RED}Please enter an existing file.{RESET}")


def manage_assemblies_menu(assemblies, input_file):
    while True:
        screen()
        print(f"\n{CYAN}--- MANAGE TARGET ASSEMBLIES (DLLs) ---{RESET}")
        items = sorted(assemblies)
        if not items:
            print(f"{RED}  (No assemblies selected!){RESET}")
        else:
            for i, name in enumerate(items, 1):
                print(f"  {i}. {name}")
        print("-" * 40)
        print("  [+] Add DLL name (e.g. +MyMod.dll)")
        print("  [-] Remove by number (e.g. -1)")
        print("  [c] Clear all")
        print("  [r] Reset to default")
        print("  [d] Detect & select DLLs from dump")
        print("  [0] Back")
        raw = input(f"{YELLOW}Choice > {RESET}").strip()
        if raw in ('0', ''):
            return
        if raw.lower() == 'c':
            assemblies.clear()
        elif raw.lower() == 'r':
            assemblies.clear()
            assemblies.update(DEFAULT_GAME_ASSEMBLIES)
        elif raw.lower() == 'd':
            screen()
            if not input_file or not input_file.is_file():
                print('Select a valid dump.cs first.')
                pause()
                continue
            _, available = read_images(input_file)
            for i, name in enumerate(available, 1):
                mark = '*' if name in assemblies else ' '
                print(f'  [{i}] [{mark}] {name}')
            selected = input('Numbers to toggle (0 = Back): ').replace(',', ' ').split()
            for num in selected:
                if num.isdigit() and 1 <= int(num) <= len(available):
                    name = available[int(num) - 1]
                    if name in assemblies:
                        assemblies.remove(name)
                    else:
                        assemblies.add(name)
        elif raw.startswith('-'):
            for num in raw.replace('-', ' ').replace(',', ' ').split():
                if num.isdigit() and 1 <= int(num) <= len(items):
                    assemblies.discard(items[int(num) - 1])
        else:
            for name in raw.lstrip('+').replace(',', ' ').split():
                name = name.lstrip('+')
                if name:
                    name = name if name.lower().endswith('.dll') else name + '.dll'
                    if name.lower() not in {a.lower() for a in assemblies}:
                        assemblies.add(name)


def run_filter_menu(assemblies=None, keywords=None, input_file=None, output_file=None):
    assemblies = set(DEFAULT_GAME_ASSEMBLIES) if assemblies is None else assemblies
    keywords = list(DEFAULT_KEYWORDS) if keywords is None else keywords
    input_file = Path(input_file) if input_file else auto_detect_dump_file()
    output_file = Path(output_file or 'filtered_dnspy_dump.txt')
    while True:
        screen()
        print(f'\n{CYAN}--- IL2CPP DUMP FILTER ---{RESET}')
        print(f'  1. Input dump.cs : {input_file or "NOT SELECTED"}')
        print(f'  2. Output file   : {output_file}')
        print(f'  3. Manage DLLs   : {len(assemblies)} selected')
        print(f'  4. Keywords count: {len(keywords)}')
        print('  5. Add keyword')
        print('  6. Start Filtering')
        print('  0. Back')
        print('-' * 40)
        choice = input(f'{YELLOW}Choose [0-6] > {RESET}').strip()
        if choice == '0':
            return
        if choice == '1':
            selected = ask_file('Path to dump.cs')
            if selected:
                input_file = selected
        elif choice == '2':
            raw = input('Output file path (0 = Back): ').strip()
            if raw and raw != '0':
                output_file = path_value(raw)
        elif choice == '3':
            manage_assemblies_menu(assemblies, input_file)
        elif choice == '4':
            screen()
            print('\n' + ', '.join(keywords))
            pause()
        elif choice == '5':
            raw = input('New keyword (0 = Back): ').strip().lower()
            if raw and raw != '0' and raw not in keywords:
                keywords.append(raw)
        elif choice == '6':
            screen()
            try:
                if not input_file or not input_file.is_file():
                    raise ValueError('Select a valid dump.cs first.')
                if not assemblies:
                    raise ValueError('Select at least one target DLL first.')
                parse_dump(input_file, output_file, assemblies, keywords)
            except Exception as exc:
                print(f'{RED}Error: {exc}{RESET}')
            pause()


def find_dumper(explicit=None):
    if explicit:
        path = path_value(explicit)
        if not path.is_file():
            raise ValueError(f'Dumper not found: {path}')
        return path
    for folder in (Path.cwd(), SCRIPT_DIR):
        for name in ('Il2CppDumper.exe', 'il2cppdumper.exe'):
            path = folder / name
            if path.is_file():
                return path.resolve()
    return None


def run_dumper(lib, metadata, out, explicit=None):
    exe = find_dumper(explicit)
    if exe is None:
        print('Il2CppDumper.exe not found; recovered metadata is available.')
        return False
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    command = [str(exe), str(Path(lib).resolve()), str(Path(metadata).resolve()), str(out)]
    print('Running:', subprocess.list2cmdline(command))
    result = subprocess.run(command, cwd=str(exe.parent), check=False)
    if result.returncode:
        raise RuntimeError(f'Il2CppDumper exited with code {result.returncode}')
    return True


def recovery_menu():
    screen()
    print(f'\n{CYAN}--- METADATA RECOVERY WIZARD ---{RESET}')
    print(f'  {CYAN}[1]{RESET} APK')
    print(f'  {CYAN}[2]{RESET} Extracted library + metadata')
    print(f'  {CYAN}[0]{RESET} Back')
    print('-' * 40)
    mode = input(f'{YELLOW}Choose [0-2] > {RESET}').strip()
    if mode not in ('1', '2'):
        return
    try:
        first = ask_file('APK path' if mode == '1' else 'libil2cpp.so path')
        if first is None:
            return
        meta = None if mode == '1' else ask_file('Metadata / sysinfo.dat path')
        if mode == '2' and meta is None:
            return
        raw = input('Output directory [./il2cpp_result] (0 = Back): ').strip()
        if raw == '0':
            return
        out = path_value(raw or './il2cpp_result')
        out.mkdir(parents=True, exist_ok=True)
        lib = first
        if mode == '1':
            lib, meta = apk_inputs(first, out)
        recovered, _ = process(lib, meta, out)
        raw = input('Il2CppDumper.exe path [Enter = auto-detect, 0 = skip]: ').strip()
        if raw != '0':
            run_dumper(lib, recovered, out / 'dump', raw or None)
    except Exception as exc:
        print(f'{RED}Error: {exc}{RESET}')
    pause()


def interactive_menu():
    assemblies = set(DEFAULT_GAME_ASSEMBLIES)
    keywords = list(DEFAULT_KEYWORDS)
    while True:
        screen()
        print(f'  {CYAN}[1]{RESET} Recover metadata (Run Il2CppDumper)')
        print(f'  {CYAN}[2]{RESET} Filter dump.cs (dnSpy cleanup)')
        print(f'  {CYAN}[0]{RESET} Exit')
        print('-' * 40)
        choice = input(f'{YELLOW}Choose [0-2] > {RESET}').strip()
        if choice == '0':
            return
        if choice == '1':
            recovery_menu()
        elif choice == '2':
            run_filter_menu(assemblies, keywords)


def main():
    ap = argparse.ArgumentParser(description='Il2Cpp Windows Dumper & Filter Suite')
    ap.add_argument('--apk', help='APK containing library and metadata')
    ap.add_argument('--lib', help='Extracted libil2cpp.so')
    ap.add_argument('--metadata', help='Metadata / sysinfo.dat file')
    ap.add_argument('--out', default='./il2cpp_result')
    ap.add_argument('--dumper-exe')
    ap.add_argument('--no-dump', action='store_true')
    ap.add_argument('-f', '--filter', action='store_true')
    ap.add_argument('-fm', '--filter-menu', action='store_true')
    ap.add_argument('-fi', '--filter-input')
    ap.add_argument('-fo', '--filter-out', default='filtered_dnspy_dump.txt')
    ap.add_argument('-k', '--keywords', nargs='+', help='Additional keywords')
    ap.add_argument('-a', '--assemblies', nargs='+', help='Target DLL names')
    args = ap.parse_args()
    assemblies = set(args.assemblies or DEFAULT_GAME_ASSEMBLIES)
    keywords = list(DEFAULT_KEYWORDS)
    for keyword in args.keywords or []:
        if keyword.strip() and keyword.lower() not in keywords:
            keywords.append(keyword.lower())
    try:
        if args.filter_menu:
            run_filter_menu(assemblies, keywords, args.filter_input, args.filter_out)
            return 0
        if not (args.apk or args.lib or args.filter):
            if not sys.stdin.isatty():
                ap.error('Provide arguments for non-interactive use.')
            interactive_menu()
            return 0
        out = path_value(args.out)
        if args.apk and args.lib:
            ap.error('Use --apk or --lib, not both.')
        if args.apk or args.lib:
            out.mkdir(parents=True, exist_ok=True)
            if args.apk:
                lib, meta = apk_inputs(Path(args.apk), out)
            else:
                if not args.metadata:
                    ap.error('--lib requires --metadata.')
                lib, meta = Path(args.lib), Path(args.metadata)
            recovered, _ = process(lib, meta, out)
            if not args.no_dump and not run_dumper(lib, recovered, out / 'dump', args.dumper_exe):
                return 2
        if args.filter:
            source = Path(args.filter_input) if args.filter_input else (
                out / 'dump' / 'dump.cs' if args.apk or args.lib else auto_detect_dump_file()
            )
            if source is None:
                raise ValueError('No dump.cs found. Use --filter-input.')
            return 0 if parse_dump(source, Path(args.filter_out), assemblies, keywords) else 2
        return 0
    except (EOFError, KeyboardInterrupt):
        print('\nClosed.')
        return 0
    except Exception as exc:
        print(f'{RED}Error: {exc}{RESET}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())

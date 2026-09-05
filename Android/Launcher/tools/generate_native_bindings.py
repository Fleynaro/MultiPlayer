#!/usr/bin/env python3
"""Generate the documented GTA native metadata and the Python typing contract."""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
DOC = ROOT / "docs" / "Natives_top_300.md"
NATIVES = ROOT / "MultiPlayer" / "Game" / "ScriptEngine" / "Natives"

GROUPS = {
    "Entity": "entity", "Player": "player", "Ped and Appearance": "ped",
    "Vehicle": "vehicle", "Object and Pickups": "object", "Tasks and AI": "task",
    "Weapons": "weapon", "Streaming and World": "world", "HUD and Blips": "hud",
}

def snake(name: str) -> str:
    return name.lower()

def python_parameters(signature: str) -> list[str]:
    args = signature[signature.find("(") + 1:signature.rfind(")")]
    if not args.strip():
        return []
    result = []
    for index, argument in enumerate(args.split(",")):
        argument = re.sub(r"cs_type\([^)]*\)\s*", "", argument).strip()
        match = re.match(r"(.+?)\s+(\w+)$", argument)
        if not match:
            result.append(f"arg{index}: object")
            continue
        native_type, name = match.groups()
        native_type = native_type.replace("const ", "").strip()
        type_name = {"BOOL": "bool", "float": "float", "char*": "str", "const char*": "str",
                     "Vector3": "Vector3", "Hash": "Hash", "Entity": "Entity", "Ped": "Ped",
                     "Vehicle": "Vehicle", "Object": "Object", "Pickup": "Pickup", "Blip": "Blip"}.get(native_type, "int" if native_type in {"int", "Player", "Any"} else "object")
        if native_type.endswith("*") and type_name == "object":
            type_name = "int"
        result.append(f"{name}: {type_name}")
    return result

def source_signature(native_text: str, name: str) -> tuple[str, str] | None:
    hash_match = re.search(r"(?:aliases:\s*\[\"|//\s*)(0x[0-9A-Fa-f]+)", native_text)
    signature_match = re.search(
        r"(?:cs_type\([^)]*\)\s*)?([A-Za-z_][\w]*(?:\s*\*)?)\s+" + re.escape(name) + r"\s*\(([^;]*)\);",
        native_text,
    )
    if not hash_match or not signature_match:
        return None
    return hash_match.group(1), f"{signature_match.group(1)} {name}({signature_match.group(2)});"

def parameter_descriptors(signature: str) -> list[str]:
    args = signature[signature.find("(") + 1:signature.rfind(")")]
    descriptors = []
    for argument in filter(str.strip, args.split(",")):
        argument = re.sub(r"cs_type\([^)]*\)\s*", "", argument).strip()
        match = re.match(r"(.+?)\s+\w+$", argument)
        native_type = match.group(1).replace("const ", "").replace(" ", "") if match else "Any"
        if native_type in {"char*", "constchar*"}:
            native_type = "str"
        descriptors.append(native_type)
    return descriptors

def return_annotation(kind: str, descriptors: list[str]) -> str:
    base = {"void": "None", "bool": "bool", "float": "float", "vector": "Vector3",
            "string": "str", "integer": "int"}[kind]
    outputs = []
    for descriptor in descriptors:
        if not descriptor.endswith("*"):
            continue
        output_type = descriptor[:-1]
        outputs.append({"Vector3": "Vector3", "float": "float", "bool": "bool"}.get(output_type, "int"))
    if not outputs:
        return base
    return "tuple[" + ", ".join(([base] if kind != "void" else []) + outputs) + "]"

def main(output: Path, pyi: Path) -> None:
    rows = []
    group = None
    for line in DOC.read_text(encoding="utf-8").splitlines():
        heading = re.match(r"## (.+)", line)
        if heading:
            group = GROUPS.get(heading.group(1))
        row = re.match(r"\| \[([^]]+)\]\(([^)]+)\) \| ([^|]+) \| `([^`]+)` \|", line)
        if group and row:
            rows.append((group, row.group(1), row.group(2), row.group(3).strip(), row.group(4)))
    if len(rows) != 300:
        raise SystemExit(f"expected 300 documented natives, found {len(rows)}")

    header_text = "\n".join(p.read_text(encoding="utf-8") for p in NATIVES.glob("NativeGroup_*.h"))
    specs = []
    for group, name, link, description, signature in rows:
        native_doc = (DOC.parent / link).resolve()
        if not native_doc.is_file():
            raise SystemExit(f"missing linked native source for {name}: {native_doc}")
        native_text = native_doc.read_text(encoding="utf-8")
        source = source_signature(native_text, name)
        if source is None:
            raise SystemExit(f"cannot parse hash/signature for {name}: {native_doc}")
        header_match = re.search(r"(0x[0-9A-Fa-f]+)>\s+" + re.escape(name) + r"\s*;", header_text)
        hash_value = header_match.group(1) if header_match else source[0]
        # The linked source is authoritative when the legacy declaration is absent.
        if header_match is None:
            signature = source[1]
        result = signature.split(" ", 1)[0].replace("cs_type(Any)", "Any")
        args = signature[signature.find("(") + 1:signature.rfind(")")]
        argc = 0 if not args.strip() else len([part for part in args.split(",") if part.strip()])
        kind = "void" if result == "void" else "bool" if result == "BOOL" else "float" if result == "float" else "vector" if result == "Vector3" else "string" if "char*" in result else "integer"
        parameters = python_parameters(signature)
        descriptors = parameter_descriptors(signature)
        parameter_types = ",".join(descriptors)
        specs.append((group, name, snake(name), hash_value, argc, kind, parameters, parameter_types, description))

    lines = ["// Generated by tools/generate_native_bindings.py. Do not edit.", "#pragma once", "#include <array>", "#include <cstdint>", "#include <string_view>", "", "namespace client::python {", "struct GeneratedNativeSpec { std::string_view group; std::string_view original; std::string_view python_name; std::uint64_t hash; std::uint8_t argc; std::string_view result; std::string_view parameter_types; };", f"inline constexpr std::array<GeneratedNativeSpec, {len(specs)}> generated_natives{{{{"]
    lines += [f'    {{"{g}", "{n}", "{p}", {h}ULL, {a}, "{k}", "{types}"}},' for g, n, p, h, a, k, _, types, _ in specs]
    lines += ["}};", "} // namespace client::python", ""]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines), encoding="utf-8")

    pyi_lines = ['"""Strictly typed public API exposed by the Client.dll Python module."""', "", "from typing import Any, Final", "", "", "class Vector3:", "    x: float", "    y: float", "    z: float", "", "    def __init__(self, x: float, y: float, z: float) -> None: ...", "", "", "Entity: Final = int", "Ped: Final = int", "Vehicle: Final = int", "Object: Final = int", "Pickup: Final = int", "Blip: Final = int", "Hash: Final = int", "", "", "def wait(milliseconds: int, /) -> None: ...", "def stop_requested() -> bool: ...", "def invoke_native(hash: Hash, arguments: list[Any], /) -> Any: ...", ""]
    current = None
    for g, original, pyname, _, argc, kind, parameters, parameter_types, description in specs:
        if g != current:
            current = g
            pyi_lines += [f"class _{g.title()}Natives:"]
        type_name = return_annotation(kind, parameter_types.split(",") if parameter_types else [])
        params = ", ".join(parameters)
        positional = ", /" if params else ""
        pyi_lines += [f'    """{original}: {description}"""',
                      f'    def {pyname}({params}{positional}) -> {type_name}: ...']
    pyi_lines += ["", ""]
    for g in sorted({item[0] for item in specs}):
        pyi_lines.append(f"{g}: _{g.title()}Natives")
    pyi.write_text("\n".join(pyi_lines) + "\n", encoding="utf-8")

if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))

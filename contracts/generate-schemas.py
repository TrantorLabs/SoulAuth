#!/usr/bin/env python3
"""从 Rust 源码生成 openapi.yaml 的 schema 与 operation I/O 部分。

# 为什么生成而不是手写

请求/响应共 96 个类型、数百个字段。手写必然漂移，而漂移的 schema 与准确的
schema 看起来一模一样 —— 消费方按它构造请求，直到 422 才发现字段名不对。

# 它改什么、不改什么

**改**：`components.schemas` 中除 `Error` / `OAuthError` 之外的全部条目，
以及每个 operation 的 `parameters` / `requestBody` / `responses` 的 schema 引用。

**不改**：文件头注释、`servers`、`securitySchemes`、`tags`、路径与方法本身、
`security`、`x-required-permissions`、`description`。那些需要判断，由人维护，
由 `tests/conformance.rs` 的 j4 / j5 / j10 守着。

`Error` 与 `OAuthError` 手写保留：它们带着「为什么是这个形状」的说明，
而那不是能从类型推导出来的东西。

# 守卫

生成结果由 `tests/conformance.rs::j11` 断言与 Rust 结构体一致 ——
改了结构体没重跑这个脚本，测试会红。

用法：python3 contracts/generate-schemas.py
"""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
HANDCRAFTED = {"Error", "OAuthError"}

PRIMITIVES = {
    "String": "string", "str": "string", "bool": "boolean",
    "i64": "integer", "i32": "integer", "u64": "integer", "u32": "integer",
    "usize": "integer", "u8": "integer", "f64": "number", "f32": "number",
}


def rust_sources():
    # 键用相对于仓库根的路径：下面靠 `src/routes/` 前缀区分路由模块与其它源码，
    # 绝对路径会让那个判断永远为假（首版就是这样，静默生成了 0 个 schema）。
    return {
        p.relative_to(ROOT).as_posix(): p.read_text()
        for p in (ROOT / "src").rglob("*.rs")
    }


STRUCT_RE = re.compile(
    r"((?:#\[[^\]]*\]\s*|///[^\n]*\n\s*)*)(?:pub(?:\([^)]*\))? )?struct (\w+)\s*\{(.*?)\n\}",
    re.S,
)
FIELD_RE = re.compile(
    r"((?:\s*(?:#\[[^\]]*\]|///[^\n]*)\n)*)\s*(?:pub(?:\([^)]*\))? )?(\w+):\s*([^,\n]+),"
)


def collect_structs(src):
    out = {}
    for text in src.values():
        for attrs, name, body in STRUCT_RE.findall(text):
            if "Serialize" not in attrs and "Deserialize" not in attrs:
                continue
            fields = []
            for fattrs, fname, ftype in FIELD_RE.findall(body):
                if "skip_serializing" in fattrs and "skip_serializing_if" not in fattrs:
                    continue
                rn = re.search(r'rename\s*=\s*"([^"]+)"', fattrs)
                fields.append({
                    "name": rn.group(1) if rn else fname,
                    "rust": ftype.strip(),
                    # `Option<T>` 与带 serde default 的字段都不是必填。
                    "optional": ftype.strip().startswith("Option<") or "default" in fattrs,
                })
            if fields:
                out[name] = fields
    return out


def collect_handlers(src):
    out = {}
    for path, text in src.items():
        if not path.startswith("src/routes/"):
            continue
        mod = pathlib.Path(path).stem
        for m in re.finditer(r"^(?:pub )?async fn (\w+)\s*\(", text, re.M):
            i, depth = m.end() - 1, 0
            while i < len(text):
                if text[i] == "(":
                    depth += 1
                elif text[i] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                i += 1
            sig = text[m.start():i + 1]
            ret = text[i + 1:text.find("{", i)]

            def short(x):
                if not x:
                    return None
                x = x.strip()
                arr = x.startswith("Vec<")
                if arr:
                    x = x[4:].rstrip(">")
                x = x.split("::")[-1].rstrip(">")
                return ("[]" + x) if arr else x

            body = re.search(r"Json\(\s*\w+\s*\):\s*Json<([\w:]+)>", sig)
            query = re.search(r"Query\(\s*\w+\s*\):\s*Query<([\w:]+)>", sig)
            resp = re.findall(r"Json<([\w:<>]+)>", ret)
            out[f"{mod}_{m.group(1)}"] = {
                "request": short(body.group(1)) if body else None,
                "query": short(query.group(1)) if query else None,
                "response": short(resp[0]) if resp else None,
                "status_only": "StatusCode" in ret and not resp,
            }
    return out


def json_type(rust, structs):
    r = rust.strip()
    optional = r.startswith("Option<")
    if optional:
        r = r[7:].rstrip(">")
    array = r.startswith("Vec<")
    if array:
        r = r[4:].rstrip(">")
    base = r.split("::")[-1].rstrip(">")

    if base in ("DateTime<Utc>", "DateTime"):
        node = {"type": "string", "format": "date-time"}
    elif base in ("Thing", "RecordId"):
        node = {"type": "string"}
    elif base == "Value":
        node = {"type": "object"}
    elif base in PRIMITIVES:
        node = {"type": PRIMITIVES[base]}
    elif base in structs:
        node = {"$ref": f"#/components/schemas/{base}"}
    else:
        node = {"type": "object"}

    if array:
        node = {"type": "array", "items": node}
    return node, optional


def main() -> int:
    src = rust_sources()
    structs = collect_structs(src)
    handlers = collect_handlers(src)

    # 只保留路由真正引用到的类型，以及它们传递引用到的类型。
    used, queue = set(), []
    for h in handlers.values():
        queue += [h[k] for k in ("request", "query", "response") if h[k]]
    while queue:
        name = queue.pop()
        name = name[2:] if name.startswith("[]") else name
        if name in used or name not in structs:
            continue
        used.add(name)
        for f in structs[name]:
            node, _ = json_type(f["rust"], structs)
            ref = node.get("$ref") or (node.get("items") or {}).get("$ref")
            if ref:
                queue.append(ref.rsplit("/", 1)[-1])

    schemas = {}
    for name in sorted(used):
        props, required = {}, []
        for f in structs[name]:
            node, optional = json_type(f["rust"], structs)
            props[f["name"]] = node
            if not optional:
                required.append(f["name"])
        schemas[name] = {"type": "object", "properties": props}
        if required:
            schemas[name]["required"] = required

    payload = {"schemas": schemas, "handlers": handlers}
    (ROOT / "contracts" / "schemas.generated.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )
    print(f"  ✓ {len(schemas)} 个 schema · {sum(1 for h in handlers.values() if h['request'])} 个请求体"
          f" · {sum(1 for h in handlers.values() if h['response'])} 个响应")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

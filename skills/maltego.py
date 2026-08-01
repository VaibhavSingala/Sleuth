"""Maltego bridge: build OSINT entity graphs and export GraphML / CSV.

Use during recon to collect Domain / IP / Email / URL / DNS entities, link
them, then export a file Maltego can open (Graph → Import → GraphML, or
Import Table for CSV). Graphs persist under skills/.maltego/.
"""

from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from xml.sax.saxutils import escape

_GRAPH_DIR = Path(__file__).resolve().parent / ".maltego"
_DEFAULT_GRAPH = "default"

# Maltego type → (property name, display name) for the primary value field.
_VALUE_PROP: dict[str, tuple[str, str]] = {
    "maltego.Domain": ("fqdn", "Domain Name"),
    "maltego.DNSName": ("fqdn", "DNS Name"),
    "maltego.IPv4Address": ("ipv4-address", "IP Address"),
    "maltego.IPv6Address": ("ipv6-address", "IPv6 Address"),
    "maltego.Website": ("website", "Website"),
    "maltego.URL": ("url", "URL"),
    "maltego.EmailAddress": ("email", "Email Address"),
    "maltego.Person": ("person.fullnamenames", "Person"),
    "maltego.Alias": ("alias", "Alias"),
    "maltego.PhoneNumber": ("phonenumber", "Phone Number"),
    "maltego.Company": ("title", "Company"),
    "maltego.Organization": ("title", "Organization"),
    "maltego.AS": ("as.number", "AS Number"),
    "maltego.NSRecord": ("fqdn", "NS Record"),
    "maltego.MXRecord": ("fqdn", "MX Record"),
    "maltego.Phrase": ("text", "Text"),
    "maltego.Hash": ("properties.hash", "Hash"),
    "maltego.Location": ("location.name", "Location"),
}

# Short aliases the model / operator can type instead of full maltego.* names.
_ALIASES: dict[str, str] = {
    "domain": "maltego.Domain",
    "dns": "maltego.DNSName",
    "dnsname": "maltego.DNSName",
    "ip": "maltego.IPv4Address",
    "ipv4": "maltego.IPv4Address",
    "ipv6": "maltego.IPv6Address",
    "website": "maltego.Website",
    "url": "maltego.URL",
    "email": "maltego.EmailAddress",
    "person": "maltego.Person",
    "alias": "maltego.Alias",
    "phone": "maltego.PhoneNumber",
    "company": "maltego.Company",
    "org": "maltego.Organization",
    "as": "maltego.AS",
    "asn": "maltego.AS",
    "ns": "maltego.NSRecord",
    "mx": "maltego.MXRecord",
    "phrase": "maltego.Phrase",
    "hash": "maltego.Hash",
    "location": "maltego.Location",
}

Action = Literal[
    "add_entity",
    "add_link",
    "list",
    "clear",
    "types",
    "infer",
    "from_text",
    "export_graphml",
    "export_csv",
    "import_graphml",
    "seed",
]

_MTG_NS = "http://maltego.paterva.com/xml/mtgx"
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_IPV6_RE = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.I
)
_ASN_RE = re.compile(r"\bAS(\d{1,10})\b", re.I)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_dir() -> None:
    _GRAPH_DIR.mkdir(parents=True, exist_ok=True)


def _graph_path(name: str) -> Path:
    safe = re.sub(r"[^a-zA-Z0-9_\-]+", "_", (name or _DEFAULT_GRAPH).strip()) or _DEFAULT_GRAPH
    return _GRAPH_DIR / f"{safe}.json"


def _empty_graph(name: str) -> dict[str, Any]:
    return {
        "name": name or _DEFAULT_GRAPH,
        "updated": _now(),
        "entities": [],  # {id, type, value, properties}
        "links": [],  # {id, source, target, label}
        "_next_id": 1,
    }


def _load(name: str) -> dict[str, Any]:
    path = _graph_path(name)
    if not path.is_file():
        return _empty_graph(name)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "entities" in data:
            return data
    except (json.JSONDecodeError, OSError):
        pass
    return _empty_graph(name)


def _save(graph: dict[str, Any]) -> Path:
    _ensure_dir()
    graph["updated"] = _now()
    path = _graph_path(graph.get("name", _DEFAULT_GRAPH))
    path.write_text(json.dumps(graph, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def _resolve_type(entity_type: str) -> str:
    t = (entity_type or "").strip()
    if not t:
        return "maltego.Phrase"
    low = t.lower()
    if low in _ALIASES:
        return _ALIASES[low]
    if t.startswith("maltego."):
        return t
    # Allow Domain / IPv4Address without prefix
    cand = f"maltego.{t}" if not t.startswith("maltego.") else t
    if cand in _VALUE_PROP or cand.lower() in {k.lower() for k in _VALUE_PROP}:
        for k in _VALUE_PROP:
            if k.lower() == cand.lower():
                return k
    return t if t.startswith("maltego.") else f"maltego.{t}"


def _infer_type(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return "maltego.Phrase"
    if _EMAIL_RE.fullmatch(v):
        return "maltego.EmailAddress"
    if _IPV4_RE.fullmatch(v):
        return "maltego.IPv4Address"
    if _IPV6_RE.fullmatch(v):
        return "maltego.IPv6Address"
    if v.lower().startswith(("http://", "https://")):
        # bare host → Website; path-heavy → URL
        from urllib.parse import urlparse

        p = urlparse(v)
        if p.path in ("", "/") and not p.query:
            return "maltego.Website"
        return "maltego.URL"
    if _ASN_RE.fullmatch(v):
        return "maltego.AS"
    if _DOMAIN_RE.fullmatch(v) and not v.replace(".", "").isdigit():
        return "maltego.Domain"
    return "maltego.Phrase"


def _find_entity(graph: dict[str, Any], value: str, entity_type: str = "") -> dict | None:
    v = value.strip().lower()
    et = _resolve_type(entity_type) if entity_type else ""
    for ent in graph["entities"]:
        if ent["value"].strip().lower() != v:
            continue
        if et and ent["type"] != et:
            continue
        return ent
    return None


def _add_entity(
    graph_name: str,
    value: str,
    entity_type: str = "",
    properties: str = "",
) -> dict[str, Any]:
    value = (value or "").strip()
    if not value:
        return {"ok": False, "error": "value is required for add_entity."}

    et = _resolve_type(entity_type) if entity_type.strip() else _infer_type(value)
    graph = _load(graph_name)

    existing = _find_entity(graph, value, et)
    if existing:
        return {
            "ok": True,
            "message": "entity already on graph",
            "entity": existing,
            "graph": graph["name"],
        }

    props: dict[str, str] = {}
    if properties.strip():
        try:
            parsed = json.loads(properties)
            if isinstance(parsed, dict):
                props = {str(k): str(v) for k, v in parsed.items()}
        except json.JSONDecodeError:
            # key=value;key2=value2
            for part in re.split(r"[;,\n]+", properties):
                if "=" in part:
                    k, val = part.split("=", 1)
                    props[k.strip()] = val.strip()

    ent = {
        "id": f"n{graph['_next_id']}",
        "type": et,
        "value": value,
        "properties": props,
    }
    graph["_next_id"] += 1
    graph["entities"].append(ent)
    path = _save(graph)
    return {
        "ok": True,
        "message": f"added {et} :: {value}",
        "entity": ent,
        "graph": graph["name"],
        "path": str(path),
        "entity_count": len(graph["entities"]),
    }


def _add_link(
    graph_name: str,
    source: str,
    target: str,
    label: str = "",
) -> dict[str, Any]:
    source, target = (source or "").strip(), (target or "").strip()
    if not source or not target:
        return {"ok": False, "error": "source and target values are required."}

    graph = _load(graph_name)
    src = _find_entity(graph, source) or _find_entity(graph, source, "")
    # allow id lookup
    if not src:
        src = next((e for e in graph["entities"] if e["id"] == source), None)
    tgt = _find_entity(graph, target)
    if not tgt:
        tgt = next((e for e in graph["entities"] if e["id"] == target), None)
    if not src or not tgt:
        missing = []
        if not src:
            missing.append(f"source '{source}'")
        if not tgt:
            missing.append(f"target '{target}'")
        return {
            "ok": False,
            "error": f"entity not found: {', '.join(missing)}. add_entity first.",
        }

    for link in graph["links"]:
        if link["source"] == src["id"] and link["target"] == tgt["id"]:
            return {"ok": True, "message": "link already exists", "link": link}

    link = {
        "id": f"e{graph['_next_id']}",
        "source": src["id"],
        "target": tgt["id"],
        "label": (label or "").strip() or "related",
    }
    graph["_next_id"] += 1
    graph["links"].append(link)
    path = _save(graph)
    return {
        "ok": True,
        "message": f"linked {src['value']} -> {tgt['value']}",
        "link": link,
        "path": str(path),
    }


def _list_graph(graph_name: str) -> dict[str, Any]:
    graph = _load(graph_name)
    return {
        "ok": True,
        "graph": graph["name"],
        "updated": graph.get("updated"),
        "entity_count": len(graph["entities"]),
        "link_count": len(graph["links"]),
        "entities": graph["entities"],
        "links": graph["links"],
        "hint": "export_graphml or export_csv to pull into Maltego.",
    }


def _clear(graph_name: str) -> dict[str, Any]:
    graph = _empty_graph(graph_name)
    path = _save(graph)
    return {"ok": True, "message": f"cleared graph '{graph['name']}'", "path": str(path)}


def _types() -> dict[str, Any]:
    return {
        "ok": True,
        "types": sorted(_VALUE_PROP.keys()),
        "aliases": dict(sorted(_ALIASES.items())),
    }


def _from_text(graph_name: str, text: str, link_to: str = "") -> dict[str, Any]:
    """Extract emails, IPs, URLs, domains, ASNs from free text and add them."""
    text = text or ""
    if not text.strip():
        return {"ok": False, "error": "text is required for from_text."}

    found: list[tuple[str, str]] = []
    for m in _EMAIL_RE.finditer(text):
        found.append(("maltego.EmailAddress", m.group(0)))
    for m in _IPV4_RE.finditer(text):
        found.append(("maltego.IPv4Address", m.group(0)))
    for m in _URL_RE.finditer(text):
        url = m.group(0).rstrip(").,;]")
        found.append((_infer_type(url), url))
    for m in _ASN_RE.finditer(text):
        found.append(("maltego.AS", f"AS{m.group(1)}"))
    # Domains last; skip ones already covered as email/URL hosts
    skip = {v.lower() for _, v in found}
    for m in _DOMAIN_RE.finditer(text):
        d = m.group(0).lower()
        if d in skip or any(d in s for s in skip):
            continue
        # skip common file-like false positives
        if d.rsplit(".", 1)[-1] in {"png", "jpg", "gif", "css", "js", "map"}:
            continue
        found.append(("maltego.Domain", d))

    added = []
    for et, val in found:
        res = _add_entity(graph_name, val, et)
        if res.get("ok") and "already" not in res.get("message", ""):
            added.append(res["entity"])
        elif res.get("ok"):
            added.append(res["entity"])

    linked = 0
    seed = (link_to or "").strip()
    if seed:
        # ensure seed exists
        _add_entity(graph_name, seed)
        for ent in added:
            if ent["value"].lower() == seed.lower():
                continue
            r = _add_link(graph_name, seed, ent["value"])
            if r.get("ok") and "already" not in r.get("message", ""):
                linked += 1

    graph = _load(graph_name)
    return {
        "ok": True,
        "message": f"extracted {len(added)} entities"
        + (f", linked {linked} to {seed}" if seed else ""),
        "added": added,
        "entity_count": len(graph["entities"]),
        "graph": graph["name"],
    }


def _seed(graph_name: str, value: str) -> dict[str, Any]:
    """Drop a Domain + Website pair for a host and link them."""
    value = (value or "").strip()
    if not value:
        return {"ok": False, "error": "value (domain or URL) is required for seed."}

    host = value
    website = value
    if value.lower().startswith(("http://", "https://")):
        from urllib.parse import urlparse

        p = urlparse(value)
        host = p.hostname or value
        website = f"{p.scheme}://{p.netloc}/"
    else:
        website = f"https://{value.strip('/')}/"

    a = _add_entity(graph_name, host, "maltego.Domain")
    b = _add_entity(graph_name, website, "maltego.Website")
    link = _add_link(graph_name, host, website, "hosts")
    return {
        "ok": True,
        "message": f"seeded domain {host}",
        "domain": a.get("entity"),
        "website": b.get("entity"),
        "link": link.get("link"),
        "graph": graph_name or _DEFAULT_GRAPH,
    }


def _entity_xml(ent: dict[str, Any], x: float, y: float) -> str:
    et = ent["type"]
    value = ent["value"]
    prop_name, display = _VALUE_PROP.get(et, ("value", "Value"))
    props = dict(ent.get("properties") or {})
    props.setdefault(prop_name, value)

    prop_xml = []
    for name, val in props.items():
        disp = display if name == prop_name else name
        prop_xml.append(
            f'          <mtg:Property displayName="{escape(disp)}" hidden="false" '
            f'name="{escape(name)}" nullable="true" readonly="false" type="string">\n'
            f"            <mtg:Value>{escape(str(val))}</mtg:Value>\n"
            f"          </mtg:Property>"
        )
    props_block = "\n".join(prop_xml)
    return (
        f'    <node id="{escape(ent["id"])}">\n'
        f'      <data key="d4">\n'
        f'        <mtg:MaltegoEntity xmlns:mtg="{_MTG_NS}" type="{escape(et)}">\n'
        f"          <mtg:Properties>\n{props_block}\n"
        f"          </mtg:Properties>\n"
        f"        </mtg:MaltegoEntity>\n"
        f"      </data>\n"
        f'      <data key="d5">\n'
        f'        <mtg:EntityRenderer xmlns:mtg="{_MTG_NS}">\n'
        f'          <mtg:Position x="{x:.1f}" y="{y:.1f}"/>\n'
        f"        </mtg:EntityRenderer>\n"
        f"      </data>\n"
        f"    </node>"
    )


def _link_xml(link: dict[str, Any]) -> str:
    label = link.get("label") or "related"
    return (
        f'    <edge id="{escape(link["id"])}" source="{escape(link["source"])}" '
        f'target="{escape(link["target"])}">\n'
        f'      <data key="d6">\n'
        f'        <mtg:MaltegoLink xmlns:mtg="{_MTG_NS}" type="maltego.link.manual-link">\n'
        f"          <mtg:Properties>\n"
        f'            <mtg:Property displayName="Label" name="maltego.link.manual-link.label" '
        f'type="string"><mtg:Value>{escape(label)}</mtg:Value></mtg:Property>\n'
        f"          </mtg:Properties>\n"
        f"        </mtg:MaltegoLink>\n"
        f"      </data>\n"
        f"    </edge>"
    )


def _export_graphml(graph_name: str, path: str = "") -> dict[str, Any]:
    graph = _load(graph_name)
    if not graph["entities"]:
        return {"ok": False, "error": "graph is empty — add_entity or from_text first."}

    cols = max(1, int(len(graph["entities"]) ** 0.5))
    nodes = []
    for i, ent in enumerate(graph["entities"]):
        x = 120.0 + (i % cols) * 220.0
        y = 120.0 + (i // cols) * 160.0
        nodes.append(_entity_xml(ent, x, y))
    edges = [_link_xml(link) for link in graph["links"]]

    xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        f'xmlns:mtg="{_MTG_NS}">\n'
        '  <key attr.name="MaltegoEntity" for="node" id="d4"/>\n'
        '  <key for="node" id="d5"/>\n'
        '  <key attr.name="MaltegoLink" for="edge" id="d6"/>\n'
        '  <graph edgedefault="directed" id="G">\n'
        + "\n".join(nodes)
        + ("\n" if edges else "")
        + "\n".join(edges)
        + "\n  </graph>\n</graphml>\n"
    )

    _ensure_dir()
    out = Path(path) if path.strip() else _GRAPH_DIR / f"{graph['name']}.graphml"
    if not out.is_absolute():
        out = _GRAPH_DIR / out.name
    out.write_text(xml, encoding="utf-8")
    return {
        "ok": True,
        "format": "graphml",
        "path": str(out),
        "entities": len(graph["entities"]),
        "links": len(graph["links"]),
        "hint": "In Maltego: Import -> Graph (GraphML) and select this file.",
    }


def _export_csv(graph_name: str, path: str = "") -> dict[str, Any]:
    graph = _load(graph_name)
    if not graph["entities"]:
        return {"ok": False, "error": "graph is empty — add_entity or from_text first."}

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["EntityType", "Value", "PropertiesJSON", "Id"])
    for ent in graph["entities"]:
        writer.writerow([
            ent["type"],
            ent["value"],
            json.dumps(ent.get("properties") or {}, ensure_ascii=False),
            ent["id"],
        ])
    writer.writerow([])
    writer.writerow(["# Links"])
    writer.writerow(["SourceId", "TargetId", "Label", "LinkId"])
    for link in graph["links"]:
        writer.writerow([link["source"], link["target"], link.get("label", ""), link["id"]])

    _ensure_dir()
    out = Path(path) if path.strip() else _GRAPH_DIR / f"{graph['name']}.csv"
    if not out.is_absolute():
        out = _GRAPH_DIR / out.name
    out.write_text(buf.getvalue(), encoding="utf-8")
    return {
        "ok": True,
        "format": "csv",
        "path": str(out),
        "entities": len(graph["entities"]),
        "links": len(graph["links"]),
        "hint": (
            "In Maltego: Import -> Import Table / Copy Entities. "
            "Map EntityType + Value columns; re-create links manually if needed."
        ),
    }


def _import_graphml(path: str, graph_name: str = "") -> dict[str, Any]:
    if not path.strip():
        return {"ok": False, "error": "path to a .graphml file is required."}
    src = Path(path.strip())
    if not src.is_file():
        # try under .maltego
        alt = _GRAPH_DIR / src.name
        if alt.is_file():
            src = alt
        else:
            return {"ok": False, "error": f"file not found: {path}"}

    try:
        tree = ET.parse(src)
        root = tree.getroot()
    except ET.ParseError as exc:
        return {"ok": False, "error": f"invalid GraphML: {exc}"}

    # Handle default xmlns
    def local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1] if "}" in tag else tag

    name = graph_name.strip() or src.stem
    graph = _empty_graph(name)
    id_map: dict[str, str] = {}

    for node in root.iter():
        if local(node.tag) != "node":
            continue
        old_id = node.get("id") or ""
        ent_type = "maltego.Phrase"
        value = ""
        props: dict[str, str] = {}
        for data in node:
            if local(data.tag) != "data":
                continue
            for child in data:
                if local(child.tag) != "MaltegoEntity":
                    continue
                ent_type = child.get("type") or ent_type
                for props_el in child:
                    if local(props_el.tag) != "Properties":
                        continue
                    for prop in props_el:
                        if local(prop.tag) != "Property":
                            continue
                        pname = prop.get("name") or ""
                        pval = ""
                        for val_el in prop:
                            if local(val_el.tag) == "Value":
                                pval = (val_el.text or "").strip()
                        if pname:
                            props[pname] = pval
        # primary value from known prop or first prop
        prop_name, _ = _VALUE_PROP.get(ent_type, ("value", "Value"))
        value = props.get(prop_name) or next(iter(props.values()), "") or old_id
        if not value:
            continue
        new_id = f"n{graph['_next_id']}"
        graph["_next_id"] += 1
        if old_id:
            id_map[old_id] = new_id
        graph["entities"].append({
            "id": new_id,
            "type": ent_type,
            "value": value,
            "properties": props,
        })

    for edge in root.iter():
        if local(edge.tag) != "edge":
            continue
        src_id = id_map.get(edge.get("source") or "")
        tgt_id = id_map.get(edge.get("target") or "")
        if not src_id or not tgt_id:
            continue
        label = "related"
        for data in edge:
            for child in data:
                if local(child.tag) != "MaltegoLink":
                    continue
                for props_el in child:
                    for prop in props_el:
                        if local(prop.tag) != "Property":
                            continue
                        for val_el in prop:
                            if local(val_el.tag) == "Value" and val_el.text:
                                label = val_el.text.strip()
        graph["links"].append({
            "id": f"e{graph['_next_id']}",
            "source": src_id,
            "target": tgt_id,
            "label": label,
        })
        graph["_next_id"] += 1

    path_out = _save(graph)
    return {
        "ok": True,
        "message": f"imported {len(graph['entities'])} entities, {len(graph['links'])} links",
        "graph": graph["name"],
        "path": str(path_out),
        "entity_count": len(graph["entities"]),
        "link_count": len(graph["links"]),
    }


def maltego(
    action: str,
    value: str = "",
    entity_type: str = "",
    source: str = "",
    target: str = "",
    label: str = "",
    properties: str = "",
    text: str = "",
    path: str = "",
    graph: str = "",
    link_to: str = "",
) -> dict[str, Any]:
    """
    Build and export Maltego OSINT graphs (GraphML / CSV).

    Typical flow:
      1. seed / add_entity / from_text — collect Domain, IP, Email, URL, …
      2. add_link — connect related entities
      3. export_graphml — write a file Maltego can Import → Graph
         (or export_csv for Import Table)

    Args:
        action: add_entity, add_link, list, clear, types, infer, from_text,
            seed, export_graphml, export_csv, import_graphml.
        value: Entity value (domain, IP, email, URL, …) for add_entity / seed / infer.
        entity_type: Maltego type or alias (domain, ip, email, url, website, …).
            Empty = auto-infer from value.
        source: Source entity value or id (add_link).
        target: Target entity value or id (add_link).
        label: Link label (add_link).
        properties: Extra entity props as JSON object or key=value;key2=value2.
        text: Free-text recon dump to mine for entities (from_text).
        path: Output/input file path (export_* / import_graphml).
        graph: Named graph (default "default"). Stored under skills/.maltego/.
        link_to: Optional seed value to auto-link extracted entities (from_text).

    Returns:
        Dict with ok, message, and action-specific fields (path, entities, …).
    """
    action = (action or "").strip().lower().replace("-", "_")
    gname = (graph or _DEFAULT_GRAPH).strip() or _DEFAULT_GRAPH

    if action == "add_entity":
        return _add_entity(gname, value, entity_type, properties)
    if action == "add_link":
        return _add_link(gname, source, target, label)
    if action == "list":
        return _list_graph(gname)
    if action == "clear":
        return _clear(gname)
    if action == "types":
        return _types()
    if action == "infer":
        if not value.strip():
            return {"ok": False, "error": "value is required for infer."}
        et = _infer_type(value)
        return {"ok": True, "value": value.strip(), "entity_type": et}
    if action == "from_text":
        return _from_text(gname, text or value, link_to)
    if action == "seed":
        return _seed(gname, value)
    if action == "export_graphml":
        return _export_graphml(gname, path)
    if action == "export_csv":
        return _export_csv(gname, path)
    if action == "import_graphml":
        return _import_graphml(path, gname)

    return {
        "ok": False,
        "error": (
            f"Unknown action '{action}'. Use one of: add_entity, add_link, list, "
            "clear, types, infer, from_text, seed, export_graphml, export_csv, "
            "import_graphml."
        ),
    }

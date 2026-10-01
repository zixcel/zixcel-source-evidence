"""Bounded, exact-baseline extraction. Continuations are not authorization tokens."""
from .model import Code, EvidenceError, SymbolRef, SourceFileRef, canonical, digest, unpack


def build_packet(index, subject, limits, continuation, relations=(), effects=()):
    limits.validate()
    symbol = index.source_evidence(subject)
    revision = index.evidence_revision(subject)
    fingerprint = digest(revision)
    selection = digest([[r.value for r in relations], [e.value for e in effects], limits.max_depth])
    if continuation and (continuation.get("digest") != fingerprint or continuation.get("subject") != subject.value
                         or continuation.get("selection") != selection):
        raise EvidenceError(Code.StaleIndex, "packet continuation baseline changed")
    positions = dict(continuation.get("positions", {})) if continuation else {}
    source_offset = continuation.get("source_offset", 0) if continuation else 0
    if type(source_offset) is not int or source_offset < 0:
        raise EvidenceError(Code.InvalidEvidence, "source continuation offset")
    if any(type(n) is not int or n < 0 for n in positions.values()):
        raise EvidenceError(Code.InvalidEvidence, "continuation offsets")
    graph = index.transitive_dependencies(subject, max_depth=limits.max_depth)
    reverse = index.dependents_of(subject)
    selected_edges = [e for e in graph["edges"] if not relations or e["kind"] in relations]
    reverse = [e for e in reverse if not relations or e["kind"] in relations or ("ReverseCall" in relations and e["kind"] == "Call")]
    type_ids = sorted({e["target"] for e in selected_edges if e["kind"] == "TypeReference" and e["target"]})
    from .model import TypeRef
    types = [index.type(TypeRef(t)) for t in type_ids]
    sources = []
    if isinstance(subject, SourceFileRef):
        sources.append({"symbol": None, "file": subject.value, "line": 1,
                        "source_digest": symbol["body_digest"], "text": symbol["source"]})
    for identity in graph["subjects"]:
        row = index.db.execute("SELECT data FROM symbols WHERE id=?", (identity,)).fetchone()
        if row:
            item = unpack(row[0])
            sources.append({"symbol": identity, "file": item["file"], "line": item["line"],
                            "source_digest": item["body_digest"], "text": item["source"]})
    revision_descriptor = {k: v for k, v in revision.items() if k != "inputs"}
    revision_descriptor.update(representation="PagedInputSet", inputs_digest=digest(revision["inputs"]),
                               input_count=len(revision["inputs"]))
    revision_inputs = [{"ref": k, "digest": v} for k, v in sorted(revision["inputs"].items())]
    packet = {"subject": subject.value, "evidence_revision_set": revision_descriptor, "evidence_digest": fingerprint,
              "subject_kind": "Symbol" if isinstance(subject, SymbolRef) else "SourceFile",
              "owner": index.owners_of(subject),
              "symbol": {k: v for k, v in symbol.items() if k != "source"} if isinstance(subject, SymbolRef) else None,
              "source_unit": {k: v for k, v in symbol.items() if k != "source"} if isinstance(subject, SourceFileRef) else None,
              "status": "Complete", "resolution": symbol["resolution"], "missing": symbol["missing"],
              "dependencies": [], "reverse_dependencies": [], "types": [], "effects": [], "sources": [],
              "revision_inputs": [], "page_start": positions,
              "omitted": [], "continuation": None}
    if relations:
        packet["requested_relations"] = [r.value for r in relations]
    if effects:
        packet["requested_effects"] = [e.value for e in effects]
    categories = [("dependencies", selected_edges, limits.max_dependencies),
                  ("reverse_dependencies", reverse, limits.max_reverse_dependencies),
                  ("types", types, limits.max_types),
                  ("effects", [e for e in index.effects_of(subject) if not effects or e["kind"] in effects] if isinstance(subject, SymbolRef) else [], limits.max_effects),
                  ("sources", sources, len(sources)),
                  ("revision_inputs", revision_inputs, limits.max_revision_inputs)]
    next_positions = {}
    source_bytes = 0
    for name, values, cap in categories:
        start = positions.get(name, 0)
        if start > len(values):
            raise EvidenceError(Code.InvalidEvidence, "continuation outside category")
        offset = start
        for item in values[start:start + cap]:
            chunked = False
            if name == "sources":
                raw = item["text"].encode()
                if source_offset > len(raw):
                    raise EvidenceError(Code.InvalidEvidence, "source continuation outside slice")
                available = min(limits.max_source_bytes-source_bytes,
                                max(0, (limits.max_bytes-len(canonical(packet).encode())-1024)//6))
                text = raw[source_offset:source_offset+available].decode("utf8", errors="ignore")
                item_bytes = len(text.encode())
                if not item_bytes and source_offset < len(raw):
                    break
                chunked = source_offset+item_bytes < len(raw)
                item = {**item, "text": text, "offset_bytes": source_offset,
                        "source_bytes": len(raw), "slice_complete": not chunked}
            else:
                item_bytes = 0
            # Reserve deterministic envelope/continuation overhead before adding an item.
            if source_bytes + item_bytes > limits.max_source_bytes:
                break
            packet[name].append(item)
            if len(canonical(packet).encode()) + 768 > limits.max_bytes:
                packet[name].pop()
                break
            source_bytes += item_bytes
            if chunked:
                source_offset += item_bytes
                break
            if name == "sources":
                source_offset = 0
            offset += 1
        if offset < len(values):
            packet["omitted"].append({"category": name, "remaining": len(values)-offset})
            next_positions[name] = offset
        else:
            next_positions[name] = len(values)
    if graph["status"] != "Complete":
        packet["omitted"].append({"category": "traversal", "reason": "increase depth/node/edge bounds"})
    if packet["omitted"]:
        packet["status"] = "Partial"
        if any(o["category"] != "traversal" for o in packet["omitted"]):
            packet["continuation"] = {"subject": subject.value, "digest": fingerprint, "selection": selection,
                                      "positions": next_positions, "source_offset": source_offset}
            if next_positions == positions and source_offset == (continuation or {}).get("source_offset", 0):
                raise EvidenceError(Code.ResourceLimitExceeded, "packet page cannot advance within requested bounds")
    if len(canonical(packet).encode()) > limits.max_bytes:
        raise EvidenceError(Code.ResourceLimitExceeded, "LimitExceeded: mandatory packet identity does not fit")
    return packet

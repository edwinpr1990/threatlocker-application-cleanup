
import io
import os
import re
from functools import lru_cache
import json
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

import pandas as pd

TIMESTAMP_PATTERN = re.compile(r"\b(\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?)?\s*UTC?)\b", re.IGNORECASE)
TRAILING_REPEAT_PATTERN = re.compile(r"\s+RE\(\d+\)\s*$", re.IGNORECASE)
WINDOWS_PATH_PATTERN = re.compile(r"(?i)([a-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]+)")
UNIX_PATH_PATTERN = re.compile(r"(/(?:[^/\r\n]+/)*[^/\r\n]+)")
HASH64_PATTERN = re.compile(r"\b([A-Fa-f0-9]{64})\b")
HASH40_PATTERN = re.compile(r"\b([A-Fa-f0-9]{40})\b")
HASH32_PATTERN = re.compile(r"\b([A-Fa-f0-9]{32})\b")
CERT_CN_PATTERN = re.compile(r"(?i)\b(cn\s*=\s*[^;|\r\n]+)")
LABEL_PATTERN = re.compile(
    r"(?P<label>Hostname:|Host:|Computer:|Device:|Machine:|SHA256:|Hash:|Path:|Process(?: Name| Path)?:|Image:|File:|Binary:|Cert(?:ificate|ificates)?s?:|Publisher:|Thumbprint:|Created By:|Created by:|Added by [^:]+:)",
    re.IGNORECASE,
)

INSTALLER_EXTENSIONS = {".msi", ".msp", ".msix", ".msixbundle", ".appx", ".appxbundle"}
PAIR_TYPES = {
    "ProcessPath": ("Process Path", "Path"),
    "ProcessCert": ("Process Path", "Certificate"),
    "PathCert": ("Path", "Certificate"),
    "PathCreatedBy": ("Path", "Created By"),
    "ProcessCreatedBy": ("Process Path", "Created By"),
}

STANDARD_COLUMN_ALIASES = {
    "full path": "path",
    "path": "path",
    "process path": "process_path",
    "process": "process_path",
    "created by": "created_by",
    "created by process": "created_by",
    "certificate": "certificate_primary",
    "certificates": "certificate_raw",
    "certificate(s)": "certificate_raw",
    "hash": "md5_or_sha256",
    "sha256": "sha256_hash",
    "notes": "Notes",
    "host name": "hostname",
    "hostname": "hostname",
    "date/time": "timestamp_utc",
    "count": "count",
}


def _deduplicate_columns_by_last(df: pd.DataFrame) -> pd.DataFrame:
    """
    Keep the last occurrence of duplicate column names.
    This lets parsed/normalized canonical columns replace original raw columns.
    """
    if df.columns.is_unique:
        return df
    return df.loc[:, ~df.columns.duplicated(keep="last")].copy()


@dataclass
class ParseResult:
    timestamp_utc: Optional[str]
    hostname: Optional[str]
    md5_hash: Optional[str]
    sha256_hash: Optional[str]
    path: Optional[str]
    process_path: Optional[str]
    certificate_raw: Optional[str]
    certificate_primary: Optional[str]
    certificate_all: Optional[str]
    created_by: Optional[str]
    added_by: Optional[str]


@dataclass
class RuleSettings:
    min_source_rows: int = 1
    require_path: bool = True
    max_wildcards: int = 2
    wildcard_user_profiles: bool = True
    collapse_version_dirs: bool = True
    use_heads_in_pairs: bool = True
    wildcard_head_levels: int = 3
    use_directory_head_for_grouping: bool = True
    adaptive_program_files_depth: bool = True
    dynamic_wildcard_depth: bool = True
    min_dynamic_head_depth: int = 2
    enable_rule_merging: bool = True
    include_example_notes: bool = False
    max_example_paths: int = 5
    max_example_notes: int = 1
    enable_path_compression: bool = True
    path_compression_mode: str = "balanced"
    min_compression_group_size: int = 3
    max_compression_wildcards: int = 2
    merge_sibling_paths: bool = True
    include_created_by_pairs: bool = False
    allow_three_condition_rules: bool = True
    aggressive_merge: bool = False
    allow_process_path_wildcards: bool = False
    allow_created_by_wildcards: bool = False
    enforce_high_risk_process_three_conditions: bool = True
    high_risk_process_min_conditions: int = 3
    enable_extension_family_compression: bool = True
    extension_family_min_group_size: int = 5
    extension_family_anchor_depth: int = 5


def settings_from_aggressiveness(profile: str) -> RuleSettings:
    profile = (profile or "balanced").lower()
    if profile == "conservative":
        return RuleSettings(
            wildcard_user_profiles=False,
            collapse_version_dirs=False,
            use_heads_in_pairs=False,
            wildcard_head_levels=4,
            merge_sibling_paths=False,
            include_created_by_pairs=False,
            allow_three_condition_rules=True,
            aggressive_merge=False,
            allow_process_path_wildcards=False,
            allow_created_by_wildcards=False,
        )
    if profile == "aggressive":
        return RuleSettings(
            wildcard_user_profiles=True,
            collapse_version_dirs=True,
            use_heads_in_pairs=True,
            wildcard_head_levels=2,
            merge_sibling_paths=True,
            include_created_by_pairs=True,
            allow_three_condition_rules=True,
            aggressive_merge=True,
            allow_process_path_wildcards=False,
            allow_created_by_wildcards=False,
        )
    return RuleSettings()



# Process paths that are too broad or commonly abused as LOLBins should not be allowed with only
# Path + Process or Process + Certificate. If these appear as the Process Path, require at least
# three conditions such as Path + Process Path + Certificate or Path + Process Path + Created By.
HIGH_RISK_PROCESS_BASENAMES = {
    "msiexec.exe", "explorer.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "wmic.exe", "wmiprvse.exe", "schtasks.exe",
    "certutil.exe", "bitsadmin.exe", "installutil.exe", "msbuild.exe", "reg.exe", "sc.exe", "net.exe",
    "net1.exe", "whoami.exe", "forfiles.exe", "hh.exe", "control.exe", "odbcconf.exe", "msxsl.exe",
    "curl.exe", "wget.exe", "ftp.exe", "atbroker.exe", "cmstp.exe", "dnscmd.exe", "esentutl.exe",
    "expand.exe", "makecab.exe", "mavinject.exe", "msconfig.exe", "presentationhost.exe", "syncappvpublishingserver.exe",
    "verclsid.exe", "msdt.exe", "conhost.exe", "dllhost.exe", "svchost.exe", "taskhostw.exe", "werfault.exe",
    "java.exe", "javaw.exe", "python.exe", "pythonw.exe", "node.exe", "perl.exe", "ruby.exe", "bash.exe",
}
HIGH_RISK_PROCESS_DIR_PATTERNS = (
    r"\\windows\\system32\\",
    r"\\windows\\syswow64\\",
    r"\\windows\\",
    r"\\appdata\\local\\temp\\",
    r"\\appdata\\roaming\\",
    r"\\programdata\\",
)


def basename_from_path(value: Optional[str]) -> str:
    p = normalize_path(value) or ""
    if not p:
        return ""
    return p.replace("/", "\\").rstrip("\\").split("\\")[-1].lower()


def is_high_risk_process_path(value: Optional[str]) -> bool:
    p = normalize_path(value) or ""
    if not p:
        return False
    base = basename_from_path(p)
    if base in HIGH_RISK_PROCESS_BASENAMES:
        return True
    # Script interpreters and installers in user-writable paths are treated as high risk even
    # if the executable is not in the static list.
    if any(re.search(pattern, p, re.IGNORECASE) for pattern in HIGH_RISK_PROCESS_DIR_PATTERNS):
        if base.endswith((".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js")):
            return True
    return False


def first_non_empty_from_blob(blob: object) -> Optional[str]:
    text = normalize_spaces(blob)
    if not text:
        return None
    for line in str(text).splitlines():
        line = normalize_spaces(line)
        if line:
            return line
    return text


def enforce_high_risk_process_rules(rules_df: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    if rules_df.empty or not getattr(settings, "enforce_high_risk_process_three_conditions", True):
        return rules_df
    min_conditions = int(getattr(settings, "high_risk_process_min_conditions", 3) or 3)
    result = rules_df.copy()
    for idx, row in result.iterrows():
        process_path = normalize_spaces(row.get("Process Path"))
        if not process_path or not is_high_risk_process_path(process_path):
            continue
        # Upgrade 2-condition high-risk process rules using the best evidence retained from source rows.
        if count_rule_conditions(row.to_dict()) < min_conditions:
            cert = first_non_empty_from_blob(row.get("Example Certificates")) or first_non_empty_from_blob(row.get("Example Certificate"))
            created_by = first_non_empty_from_blob(row.get("Example Created By"))
            path = first_non_empty_from_blob(row.get("Example Paths"))
            if not normalize_spaces(row.get("Certificate")) and cert:
                result.at[idx, "Certificate"] = cert
            elif not normalize_spaces(row.get("Created By")) and created_by:
                result.at[idx, "Created By"] = created_by
            elif not normalize_spaces(row.get("Path")) and path:
                result.at[idx, "Path"] = path
        result.at[idx, "Condition Count"] = count_rule_conditions(result.loc[idx].to_dict())
    return result[result.apply(lambda row: not is_high_risk_process_path(row.get("Process Path")) or count_rule_conditions(row.to_dict()) >= min_conditions, axis=1)].copy()


def extension_family_candidate(paths: List[str], settings: RuleSettings) -> Optional[str]:
    if not getattr(settings, "enable_extension_family_compression", True):
        return None
    cleaned = sorted({normalize_path(p) for p in paths if normalize_path(p)})
    if len(cleaned) < int(getattr(settings, "extension_family_min_group_size", 5)):
        return None
    parsed = [path_segments_for_suggestion(p) for p in cleaned]
    roots = {root for root, _segments, _sep, _has_file in parsed}
    seps = {sep for _root, _segments, sep, _has_file in parsed}
    if len(roots) != 1 or len(seps) != 1:
        return None
    ext_counts: Dict[str, int] = {}
    for _root, segments, _sep, has_file in parsed:
        if not has_file or not segments:
            continue
        ext = os.path.splitext(segments[-1])[1].lower()
        if ext:
            ext_counts[ext] = ext_counts.get(ext, 0) + 1
    if not ext_counts:
        return None
    ext, ext_count = sorted(ext_counts.items(), key=lambda item: item[1], reverse=True)[0]
    if ext_count < int(getattr(settings, "extension_family_min_group_size", 5)):
        return None

    root = parsed[0][0]
    sep = parsed[0][2]
    dir_lists = [segments[:-1] if has_file else segments for _root, segments, _sep, has_file in parsed]
    common: List[str] = []
    for segment_group in zip(*dir_lists):
        lowered = {segment.lower() for segment in segment_group}
        if len(lowered) == 1:
            common.append(segment_group[0])
        else:
            break
    if not common:
        return None

    # Prefer the stable vendor/product anchor before volatile version folders or repeated subcomponents.
    anchor_depth = min(len(common), int(getattr(settings, "extension_family_anchor_depth", 5)))
    if "*" in common:
        star_index = common.index("*")
        anchor_depth = max(1, star_index)  # collapse before the version wildcard
    elif any(is_volatile_path_segment(segment) for segment in common):
        first_volatile = next(i for i, segment in enumerate(common) if is_volatile_path_segment(segment))
        anchor_depth = max(1, first_volatile)
    kept = common[:anchor_depth]
    leaf = f"*{ext}" if ext else "*"
    if root == "/":
        candidate = "/" + sep.join(kept + [leaf])
    else:
        candidate = sep.join([root] + kept + [leaf])
    max_wc = int(getattr(settings, "max_compression_wildcards", getattr(settings, "max_wildcards", 2)))
    return candidate if candidate.count("*") <= max_wc else None

def normalize_spaces(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    value = str(value).strip()
    if not value or value.lower() in {"nan", "none", "[]", "{}"}:
        return None
    value = TRAILING_REPEAT_PATTERN.sub("", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value or None


def is_windows_path(value: str) -> bool:
    return bool(re.match(r"(?i)^[a-z]:[\\/]", value or ""))


def is_unix_path(value: str) -> bool:
    return bool(value and str(value).startswith("/"))


def normalize_path(value: Optional[str]) -> Optional[str]:
    value = normalize_spaces(value)
    if not value:
        return None
    return _normalize_path_cached(str(value))


@lru_cache(maxsize=200000)
def _normalize_path_cached(value: str) -> Optional[str]:
    value = value.strip('"').replace("/", "\\")
    value = re.sub(r"\\+", r"\\", value)
    return value.lower()

def parse_hashes(text: str) -> Tuple[Optional[str], Optional[str]]:
    sha256 = None
    md5 = None
    for patt, target in ((HASH64_PATTERN, "sha256"), (HASH40_PATTERN, "sha1"), (HASH32_PATTERN, "md5")):
        m = patt.search(text)
        if m:
            if target == "sha256":
                sha256 = m.group(1)
            elif target == "md5":
                md5 = m.group(1)
            break
    return md5, sha256


def split_certificates(value: Optional[str]) -> List[str]:
    value = normalize_spaces(value)
    if not value:
        return []
    if value.startswith("[") and value.endswith("]"):
        try:
            parsed = json.loads(value)
            certs = []
            for item in parsed:
                if isinstance(item, dict):
                    subject = normalize_spaces(item.get("subject"))
                    sha = normalize_spaces(item.get("sha"))
                    composed = subject or sha
                    if subject and sha:
                        composed = f"{subject} | sha={sha}"
                    if composed:
                        certs.append(composed)
            if certs:
                return certs
        except Exception:
            pass
    parts = [normalize_spaces(part) for part in re.split(r"\s*;\s*", value)]
    return [part for part in parts if part]


def choose_primary_certificate(certificates: List[str]) -> Optional[str]:
    if not certificates:
        return None
    non_ms = [c for c in certificates if "microsoft corporation" not in c.lower()]
    return (non_ms[0] if non_ms else certificates[0]).strip()


def canonical_label(label_text: str) -> str:
    label = label_text.lower().strip()
    if label.startswith(("hostname", "host", "computer", "device", "machine")):
        return "hostname"
    if label.startswith("sha256"):
        return "sha256_hash"
    if label == "hash:":
        return "hash"
    if label.startswith("path"):
        return "path"
    if label.startswith(("process", "image", "file", "binary")):
        return "process_path"
    if label.startswith(("cert", "publisher", "thumbprint")):
        return "certificate_raw"
    if label.startswith("created by"):
        return "created_by"
    if label.startswith("added by"):
        return "added_by"
    return label.rstrip(":")


def select_first(text: str, patterns: Iterable[re.Pattern]) -> Optional[str]:
    for patt in patterns:
        m = patt.search(text)
        if m:
            return normalize_spaces(m.group(1))
    return None


def parse_notes_value(note: Optional[str]) -> ParseResult:
    note = normalize_spaces(note)
    if not note:
        return ParseResult(None, None, None, None, None, None, None, None, None, None, None)

    timestamp_match = TIMESTAMP_PATTERN.search(note)
    timestamp = normalize_spaces(timestamp_match.group(1)) if timestamp_match else None

    fields: Dict[str, Optional[str]] = {
        "hostname": None,
        "hash": None,
        "sha256_hash": None,
        "path": None,
        "process_path": None,
        "certificate_raw": None,
        "created_by": None,
        "added_by": None,
    }

    matches = list(LABEL_PATTERN.finditer(note))
    for idx, match in enumerate(matches):
        key = canonical_label(match.group("label"))
        start = match.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(note)
        raw_value = normalize_spaces(note[start:end])
        fields[key] = raw_value

    path = normalize_path(fields.get("path"))
    process_path = normalize_path(fields.get("process_path"))
    if not path:
        path = select_first(note, [WINDOWS_PATH_PATTERN, UNIX_PATH_PATTERN])
        path = normalize_path(path)

    certificates = split_certificates(fields.get("certificate_raw"))
    if not certificates:
        cn = select_first(note, [CERT_CN_PATTERN])
        if cn:
            certificates = [cn]
    certificate_primary = choose_primary_certificate(certificates)
    certificate_all = "; ".join(certificates) if certificates else None

    raw_hash = normalize_spaces(fields.get("hash"))
    md5 = raw_hash if raw_hash and len(raw_hash) == 32 else None
    sha256 = normalize_spaces(fields.get("sha256_hash"))
    if raw_hash and len(raw_hash) == 64 and not sha256:
        sha256 = raw_hash
    if not md5 and not sha256:
        md5, sha256 = parse_hashes(note)

    return ParseResult(
        timestamp_utc=timestamp,
        hostname=normalize_spaces(fields.get("hostname")),
        md5_hash=md5,
        sha256_hash=sha256,
        path=path,
        process_path=process_path,
        certificate_raw=normalize_spaces(fields.get("certificate_raw")),
        certificate_primary=normalize_spaces(certificate_primary),
        certificate_all=normalize_spaces(certificate_all),
        created_by=normalize_spaces(fields.get("created_by")),
        added_by=normalize_spaces(fields.get("added_by")),
    )


def apply_user_profile_wildcard(path: str) -> str:
    path = normalize_path(path) or path
    if is_windows_path(path):
        return re.sub(r"^(c:\\users\\)[^\\]+", r"\1*", path, flags=re.IGNORECASE)
    if is_unix_path(path):
        return re.sub(r"^(/users/)[^/]+", r"\1*", path, flags=re.IGNORECASE)
    return path


def collapse_version_segments(path: str) -> str:
    sep = "\\" if "\\" in path else "/"
    segments = path.split(sep)
    for i, segment in enumerate(segments):
        if re.fullmatch(r"\d+(?:\.\d+){1,6}", segment or ""):
            segments[i] = "*"
        elif re.fullmatch(r"v\d+(?:\.\d+){1,6}", segment or "", flags=re.IGNORECASE):
            segments[i] = "*"
    return sep.join(segments)


def convert_to_normalized_path(path: Optional[str], wildcard_user_profile: bool, collapse_versions: bool) -> Optional[str]:
    p = normalize_path(path)
    if not p:
        return None
    return _convert_to_normalized_path_cached(p, bool(wildcard_user_profile), bool(collapse_versions))


@lru_cache(maxsize=200000)
def _convert_to_normalized_path_cached(path: str, wildcard_user_profile: bool, collapse_versions: bool) -> Optional[str]:
    p = path
    if wildcard_user_profile:
        p = apply_user_profile_wildcard(p)
    if collapse_versions:
        p = collapse_version_segments(p)
    return p

def shorten_leaf(path: Optional[str], preserve_installer_ext: bool = True) -> Optional[str]:
    path = normalize_path(path)
    if not path:
        return None
    if "*" in path:
        return path
    sep = "\\" if "\\" in path else "/"
    parts = path.split(sep)
    if len(parts) < 3:
        return path
    filename = parts[-1]
    ext = os.path.splitext(filename)[1].lower()
    wildcard_leaf = f"*{ext}" if preserve_installer_ext and ext in INSTALLER_EXTENSIONS else "*"
    return sep.join(parts[:-1] + [wildcard_leaf])


def split_path(path: str) -> Tuple[str, List[str], str]:
    path = normalize_path(path)
    sep = "\\" if "\\" in path else "/"
    parts = path.split(sep)
    root = parts[0]
    rest = [segment for segment in parts[1:] if segment]
    if sep == "/" and path.startswith("/"):
        root = "/"
        rest = [segment for segment in path[1:].split("/") if segment]
    return root, rest, sep


def path_looks_like_file_segment(segment: str) -> bool:
    segment = normalize_spaces(segment) or ""
    if segment == "*":
        return False
    _, ext = os.path.splitext(segment)
    return bool(ext and len(ext) <= 12)


def remove_leaf_file_segment(path: Optional[str]) -> Optional[str]:
    path = normalize_path(path)
    if not path:
        return None
    root, segments, sep = split_path(path)
    if segments and path_looks_like_file_segment(segments[-1]):
        segments = segments[:-1]
    if root == "/":
        return "/" + sep.join(segments) if segments else "/"
    return sep.join([root] + segments) if segments else root


def get_path_head(path: str, levels: int) -> str:
    root, segments, sep = split_path(path)
    if root == "/":
        return root + sep.join(segments[: max(1, levels)])
    return sep.join([root] + segments[: max(1, levels)])


def get_directory_head(path: str, levels: int) -> str:
    directory_path = remove_leaf_file_segment(path) or path
    return get_path_head(directory_path, levels)


def get_adaptive_head_levels(path: str, requested_levels: int, settings: RuleSettings) -> int:
    requested_levels = max(1, int(requested_levels or 1))
    norm = normalize_path(path) or ""
    _root, segments, _sep = split_path(norm)
    lowered = [x.lower() for x in segments]

    if not getattr(settings, "adaptive_program_files_depth", True):
        return requested_levels

    is_program_files = bool(lowered) and lowered[0] in {"program files", "program files (x86)"}
    if not is_program_files:
        return requested_levels

    # For shallow Program Files trees, do not allow the executable/file leaf to become
    # part of the grouping key. This improves examples like:
    # c:\program files\vendor\app.exe -> c:\program files\vendor
    # c:\program files\vendor\app\bin\tool.exe -> c:\program files\vendor\app
    directory_segments = segments[:-1] if segments and path_looks_like_file_segment(segments[-1]) else segments
    directory_depth = len(directory_segments)

    if directory_depth <= 0:
        return requested_levels
    if directory_depth <= 3:
        return directory_depth
    return min(max(requested_levels, 3), directory_depth)


def get_group_head(path: str, settings: RuleSettings) -> str:
    levels = get_adaptive_head_levels(path, settings.wildcard_head_levels, settings)
    if getattr(settings, "use_directory_head_for_grouping", True):
        return get_directory_head(path, levels)
    return get_path_head(path, levels)


def get_wildcard_head(
    path: str,
    levels: int,
    wildcard_user_profiles: bool,
    collapse_versions: bool,
    settings: Optional[RuleSettings] = None,
) -> str:
    norm = convert_to_normalized_path(path, wildcard_user_profiles, collapse_versions)
    if not norm:
        return ""
    sep = "\\" if "\\" in norm else "/"
    if settings is not None and getattr(settings, "use_directory_head_for_grouping", True):
        head = get_group_head(norm, settings)
    else:
        head = get_path_head(norm, levels)
    return head.rstrip(sep) + sep + "*"


def shared_prefix(paths: List[str]) -> Tuple[Optional[str], List[str], Optional[str]]:
    normalized = [normalize_path(path) for path in paths if normalize_path(path)]
    if not normalized:
        return None, [], None
    roots = {split_path(p)[0] for p in normalized}
    seps = {split_path(p)[2] for p in normalized}
    if len(roots) != 1 or len(seps) != 1:
        return None, [], None
    split_segments = [split_path(p)[1] for p in normalized]
    common: List[str] = []
    for segment_group in zip(*split_segments):
        if len(set(segment_group)) == 1:
            common.append(segment_group[0])
        else:
            break
    return list(roots)[0], common, list(seps)[0]



def normalized_path_for_suggestion(value: Optional[str], settings: RuleSettings) -> Optional[str]:
    return convert_to_normalized_path(value, settings.wildcard_user_profiles, settings.collapse_version_dirs)


def path_segments_for_suggestion(path: Optional[str]) -> Tuple[str, List[str], str, bool]:
    norm = normalize_path(path)
    if not norm:
        return "", [], "\\", False
    root, segments, sep = split_path(norm)
    has_file_leaf = bool(segments and path_looks_like_file_segment(segments[-1]))
    return root, segments, sep, has_file_leaf


def build_wildcard_from_depth(path: str, depth: int, settings: RuleSettings, include_leaf_ext: bool = True) -> Optional[str]:
    norm = normalized_path_for_suggestion(path, settings)
    if not norm:
        return None

    root, segments, sep, has_file_leaf = path_segments_for_suggestion(norm)
    if not root:
        return None

    directory_segments = segments[:-1] if has_file_leaf else segments
    if not directory_segments:
        return norm

    depth = max(1, min(int(depth), len(directory_segments)))
    kept = directory_segments[:depth]

    leaf = "*"
    if include_leaf_ext and has_file_leaf:
        ext = os.path.splitext(segments[-1])[1].lower()
        if ext in INSTALLER_EXTENSIONS:
            leaf = f"*{ext}"

    if root == "/":
        candidate = "/" + sep.join(kept + [leaf])
    else:
        candidate = sep.join([root] + kept + [leaf])

    return candidate if candidate.count("*") <= settings.max_wildcards else None


def choose_dynamic_wildcard_for_row(path: Optional[str], settings: RuleSettings) -> Optional[str]:
    norm = normalized_path_for_suggestion(path, settings)
    if not norm:
        return None

    # For one-off row suggestions, keep the filename wildcard as the safest default.
    leaf_short = shorten_leaf(norm)
    if leaf_short and leaf_short.count("*") <= settings.max_wildcards:
        return leaf_short

    root, segments, sep, has_file_leaf = path_segments_for_suggestion(norm)
    directory_segments = segments[:-1] if has_file_leaf else segments
    if not directory_segments:
        return norm

    requested = get_adaptive_head_levels(norm, settings.wildcard_head_levels, settings)
    requested = min(requested, len(directory_segments))
    return build_wildcard_from_depth(norm, requested, settings) or norm


def common_directory_prefix(paths: List[str], settings: RuleSettings) -> Tuple[Optional[str], List[str], str, List[bool], List[List[str]]]:
    normalized = [normalized_path_for_suggestion(p, settings) for p in paths]
    normalized = [p for p in normalized if p]
    if not normalized:
        return None, [], "\\", [], []

    parsed = [path_segments_for_suggestion(p) for p in normalized]
    roots = {root for root, _segments, _sep, _has_file in parsed}
    seps = [sep for _root, _segments, sep, _has_file in parsed if sep]

    if len(roots) != 1:
        return None, [], "\\", [], []

    root = parsed[0][0]
    sep = seps[0] if seps else "\\"
    has_file_flags = [has_file for _root, _segments, _sep, has_file in parsed]
    dir_segments = [segments[:-1] if has_file else segments for _root, segments, _sep, has_file in parsed]

    common: List[str] = []
    for segment_group in zip(*dir_segments):
        lowered = {segment.lower() for segment in segment_group}
        if len(lowered) == 1:
            common.append(segment_group[0])
        else:
            break

    return root, common, sep, has_file_flags, dir_segments


def choose_dynamic_wildcard_for_cluster(paths: List[str], settings: RuleSettings) -> Optional[str]:
    normalized = [normalized_path_for_suggestion(p, settings) for p in paths]
    normalized = [p for p in normalized if p]

    if not normalized:
        return None

    if len(normalized) == 1:
        return choose_dynamic_wildcard_for_row(normalized[0], settings)

    root, common, sep, has_file_flags, dir_segments = common_directory_prefix(normalized, settings)
    if not root or not common:
        return None

    min_depth = max(1, int(getattr(settings, "min_dynamic_head_depth", 2)))
    max_common_depth = len(common)
    if max_common_depth < min_depth:
        return None

    # Use the shortest common prefix that still respects the configured minimum depth.
    # Example:
    # C:\Program Files\Vendor\App1\...
    # C:\Program Files\Vendor\App2\...
    # with min depth 3 => C:\Program Files\Vendor\*
    depth = min_depth

    # For Program Files paths, avoid going broader than vendor/product level by default.
    # For Common Files vendor trees, keep: c:\program files (x86)\common files\vendor\product\*
    lowered = [x.lower() for x in common]
    if lowered and lowered[0] in {"program files", "program files (x86)"}:
        if len(lowered) > 1 and lowered[1] == "common files":
            depth = max(depth, min(4, max_common_depth))
        else:
            depth = max(depth, min(2, max_common_depth))

    depth = min(depth, max_common_depth)

    base_path = normalized[0]
    return build_wildcard_from_depth(base_path, depth, settings)


def cluster_to_wildcards(paths: List[str], settings: RuleSettings, preserve_installer_ext: bool = True) -> Optional[str]:
    if getattr(settings, "dynamic_wildcard_depth", True):
        dynamic = choose_dynamic_wildcard_for_cluster(paths, settings)
        if dynamic:
            return dynamic

    normalized = [convert_to_normalized_path(p, settings.wildcard_user_profiles, settings.collapse_version_dirs) for p in paths]
    normalized = [p for p in normalized if p]
    if len(normalized) < 2:
        return None
    root, common, sep = shared_prefix(normalized)
    if not root or not sep:
        return None
    split_segments = [split_path(p)[1] for p in normalized]
    remaining = [segments[len(common):] for segments in split_segments]
    max_wc = settings.max_wildcards

    def build(parts: List[str]) -> str:
        if root == "/":
            return "/" + sep.join(parts)
        return sep.join([root] + parts)

    if all(len(item) == 1 for item in remaining):
        extset = {os.path.splitext(item[-1])[1].lower() for item in remaining if item}
        wildcard_leaf = "*"
        if preserve_installer_ext and len(extset) == 1 and list(extset)[0] in INSTALLER_EXTENSIONS:
            wildcard_leaf = f"*{list(extset)[0]}"
        candidate = build(common + [wildcard_leaf])
        return candidate if candidate.count("*") <= max_wc else None

    if all(len(item) == 2 for item in remaining) and max_wc >= 2:
        extset = {os.path.splitext(item[-1])[1].lower() for item in remaining if item}
        wildcard_leaf = "*"
        if preserve_installer_ext and len(extset) == 1 and list(extset)[0] in INSTALLER_EXTENSIONS:
            wildcard_leaf = f"*{list(extset)[0]}"
        candidate = build(common + ["*", wildcard_leaf])
        return candidate if candidate.count("*") <= max_wc else None

    if settings.aggressive_merge:
        candidate = get_wildcard_head(normalized[0], settings.wildcard_head_levels, settings.wildcard_user_profiles, settings.collapse_version_dirs, settings)
        return candidate if candidate.count("*") <= max_wc else None
    return None


def normalize_for_pair(value: Optional[str], kind: str, settings: RuleSettings) -> Dict[str, str]:
    value = normalize_spaces(value)
    if not value:
        return {"key": "", "wildcard": ""}
    if kind in {"Path", "Process Path"}:
        norm = convert_to_normalized_path(value, settings.wildcard_user_profiles, settings.collapse_version_dirs)
        if not norm:
            return {"key": "", "wildcard": ""}
        key = get_group_head(norm, settings) if settings.use_heads_in_pairs else norm
        wildcard = norm
        if kind == "Path":
            wildcard = choose_dynamic_wildcard_for_row(norm, settings) if getattr(settings, "dynamic_wildcard_depth", True) else shorten_leaf(norm)
            wildcard = wildcard or get_wildcard_head(value, settings.wildcard_head_levels, settings.wildcard_user_profiles, settings.collapse_version_dirs, settings)
            if wildcard.count("*") > settings.max_wildcards:
                wildcard = get_wildcard_head(value, settings.wildcard_head_levels, settings.wildcard_user_profiles, settings.collapse_version_dirs, settings)
        elif settings.allow_process_path_wildcards:
            wildcard = choose_dynamic_wildcard_for_row(norm, settings) if getattr(settings, "dynamic_wildcard_depth", True) else get_wildcard_head(value, settings.wildcard_head_levels, settings.wildcard_user_profiles, settings.collapse_version_dirs, settings)
        return {"key": key, "wildcard": wildcard}
    if kind == "Certificate":
        key = ensure_certificate_o_prefix(value)
        return {"key": key or "", "wildcard": key or ""}
    if kind == "Created By":
        key = value
        wildcard = value if not settings.allow_created_by_wildcards else re.sub(r"\s+", " ", value).strip()
        return {"key": key, "wildcard": wildcard}
    return {"key": value, "wildcard": value}




def get_first_scalar(row: pd.Series, key: str):
    value = row.get(key)
    if isinstance(value, pd.Series):
        for item in value.tolist():
            norm = normalize_spaces(item) if isinstance(item, str) else item
            if pd.notna(item):
                return item
        return None
    return value

def count_conditions_from_row(row: pd.Series) -> int:
    return sum(1 for col in ["path", "process_path", "certificate_primary", "created_by"] if normalize_spaces(row.get(col)))


def count_rule_conditions(rule: Dict[str, Optional[str]]) -> int:
    return sum(1 for key in ["Path", "Process Path", "Certificate", "Created By"] if normalize_spaces(rule.get(key)))


def _rename_known_columns(df: pd.DataFrame) -> pd.DataFrame:
    rename_map = {}
    for col in df.columns:
        alias = STANDARD_COLUMN_ALIASES.get(str(col).strip().lower())
        if alias:
            rename_map[col] = alias
    return df.rename(columns=rename_map)


def apply_parsing(df: pd.DataFrame) -> pd.DataFrame:
    result = df.copy()
    result.columns = [str(col).strip() for col in result.columns]
    result = _rename_known_columns(result)

    parsed_df = pd.DataFrame(index=result.index)

    if "Notes" in result.columns:
        parsed_records = [parse_notes_value(note) for note in result["Notes"].fillna("")]
        parsed_df = pd.DataFrame([vars(item) for item in parsed_records], index=result.index)

    def pull(col: str) -> pd.Series:
        return result[col] if col in result.columns else pd.Series([None] * len(result), index=result.index)

    direct_path = pull("path").map(normalize_path)
    direct_process = pull("process_path").map(normalize_path)
    direct_created_by = pull("created_by").map(normalize_spaces)
    direct_certificate_raw = pull("certificate_raw").map(normalize_spaces)
    direct_certificate_primary = pull("certificate_primary").map(normalize_spaces)
    direct_hostname = pull("hostname").map(normalize_spaces)
    direct_timestamp = pull("timestamp_utc").map(normalize_spaces)
    direct_count = pd.to_numeric(pull("count"), errors="coerce").fillna(1).astype(int)

    if "md5_or_sha256" in result.columns:
        mixed_hash = pull("md5_or_sha256").map(normalize_spaces)
        direct_md5 = mixed_hash.where(mixed_hash.fillna("").str.len() == 32)
        direct_sha256_from_hash = mixed_hash.where(mixed_hash.fillna("").str.len() == 64)
    else:
        direct_md5 = pd.Series([None] * len(result), index=result.index)
        direct_sha256_from_hash = pd.Series([None] * len(result), index=result.index)

    direct_sha256 = pull("sha256_hash").map(normalize_spaces).combine_first(direct_sha256_from_hash)

    cert_series = direct_certificate_primary.copy()
    if direct_certificate_raw.notna().any():
        parsed_certs = direct_certificate_raw.map(split_certificates)
        cert_series = cert_series.combine_first(parsed_certs.map(choose_primary_certificate))
        certificate_all = parsed_certs.map(lambda items: "; ".join(items) if items else None)
    else:
        certificate_all = pd.Series([None] * len(result), index=result.index)

    for col_name, series in [
        ("path", direct_path),
        ("process_path", direct_process),
        ("created_by", direct_created_by),
        ("certificate_raw", direct_certificate_raw),
        ("certificate_primary", cert_series),
        ("certificate_all", certificate_all),
        ("hostname", direct_hostname),
        ("timestamp_utc", direct_timestamp),
        ("md5_hash", direct_md5),
        ("sha256_hash", direct_sha256),
    ]:
        if col_name not in parsed_df.columns:
            parsed_df[col_name] = None
        parsed_df[col_name] = parsed_df[col_name].combine_first(series)

    parsed_df["path"] = parsed_df["path"].map(normalize_path)
    parsed_df["process_path"] = parsed_df["process_path"].map(normalize_path)
    parsed_df["certificate_primary"] = parsed_df["certificate_primary"].map(normalize_spaces)
    parsed_df["created_by"] = parsed_df["created_by"].map(normalize_spaces)
    parsed_df["wildcard_path"] = parsed_df["path"].map(shorten_leaf)
    parsed_df["condition_count"] = parsed_df.apply(count_conditions_from_row, axis=1)
    parsed_df["count"] = direct_count
    parsed_df["row_fingerprint"] = parsed_df.apply(
        lambda row: " | ".join(
            [
                normalize_spaces(row.get("path")) or "",
                normalize_spaces(row.get("process_path")) or "",
                normalize_spaces(row.get("certificate_primary")) or "",
                normalize_spaces(row.get("created_by")) or "",
                normalize_spaces(row.get("sha256_hash")) or normalize_spaces(row.get("md5_hash")) or "",
            ]
        ),
        axis=1,
    )

    result = pd.concat([result, parsed_df], axis=1)
    result = _deduplicate_columns_by_last(result)
    return result


def build_candidate_pairs(df: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    working = df.copy().drop_duplicates(subset=["row_fingerprint"], keep="first")
    records: List[Dict[str, object]] = []
    pair_types = ["ProcessPath", "ProcessCert", "PathCert"]
    if settings.include_created_by_pairs:
        pair_types += ["PathCreatedBy", "ProcessCreatedBy"]

    for idx, row in working.reset_index(drop=True).iterrows():
        source = {
            "Path": normalize_spaces(get_first_scalar(row, "path")),
            "Process Path": normalize_spaces(get_first_scalar(row, "process_path")),
            "Certificate": normalize_spaces(get_first_scalar(row, "certificate_primary")),
            "Created By": normalize_spaces(get_first_scalar(row, "created_by")),
        }
        raw_count = get_first_scalar(row, "count")
        row_count = int(raw_count) if pd.notna(raw_count) and str(raw_count).strip() else 1
        for pair_type in pair_types:
            a_kind, b_kind = PAIR_TYPES[pair_type]
            a_val = source.get(a_kind)
            b_val = source.get(b_kind)
            if not a_val or not b_val:
                continue
            a_norm = normalize_for_pair(a_val, a_kind, settings)
            b_norm = normalize_for_pair(b_val, b_kind, settings)
            if not a_norm["key"] or not b_norm["key"]:
                continue
            records.append(
                {
                    "PairType": pair_type,
                    "Condition1Kind": a_kind,
                    "Condition1": a_val,
                    "Condition1Key": a_norm["key"],
                    "Condition1WC": a_norm["wildcard"],
                    "Condition2Kind": b_kind,
                    "Condition2": b_val,
                    "Condition2Key": b_norm["key"],
                    "Condition2WC": b_norm["wildcard"],
                    "OriginRow": idx + 1,
                    "OccurrencesWeighted": row_count,
                    "Path": source["Path"],
                    "Process Path": source["Process Path"],
                    "Certificate": source["Certificate"],
                    "Created By": source["Created By"],
                    "Hash": normalize_spaces(get_first_scalar(row, "sha256_hash")) or normalize_spaces(get_first_scalar(row, "md5_hash")),
                    "Host Name": normalize_spaces(get_first_scalar(row, "hostname")),
                    "Timestamp": normalize_spaces(get_first_scalar(row, "timestamp_utc")),
                    "Notes": get_first_scalar(row, "Notes"),
                }
            )
    detailed_df = pd.DataFrame(records)
    if detailed_df.empty:
        return detailed_df

    group_cols = [
        "PairType",
        "Condition1Kind",
        "Condition1Key",
        "Condition1WC",
        "Condition2Kind",
        "Condition2Key",
        "Condition2WC",
    ]
    weight_col = "WeightedCount" if "WeightedCount" in detailed_df.columns else ("Count" if "Count" in detailed_df.columns else None)

    agg_map = {
        "Occurrences": ("OriginRow", "count"),
        "SampleCondition1": ("Condition1", "first"),
        "SampleCondition2": ("Condition2", "first"),
        "ExamplePaths": ("Path", lambda s: "\n".join(sorted({x for x in s.dropna()})[: int(getattr(settings, "max_example_paths", 5))])),
    }
    if weight_col:
        agg_map["WeightedCount"] = (weight_col, "sum")
    else:
        detailed_df["WeightedCount"] = 1
        agg_map["WeightedCount"] = ("WeightedCount", "sum")

    if getattr(settings, "include_example_notes", False):
        agg_map["ExampleNotes"] = ("Notes", lambda s: "\n---\n".join([str(x) for x in s.dropna().head(int(getattr(settings, "max_example_notes", 1)))]))
    else:
        agg_map["ExampleNotes"] = ("Notes", "first")

    agg_df = detailed_df.groupby(group_cols, dropna=False).agg(**agg_map).reset_index()
    return agg_df.sort_values(["WeightedCount", "Occurrences", "PairType", "Condition1Key", "Condition2Key"], ascending=[False, False, True, True, True]).reset_index(drop=True)



def is_volatile_path_segment(segment: Optional[str]) -> bool:
    segment = normalize_spaces(segment) or ""
    if not segment or segment == "*":
        return False

    s = segment.lower().strip()

    # GUIDs
    if re.fullmatch(r"\{?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}?", s):
        return True

    # Tanium/temp/random directory patterns such as 004354ly, 0a1v3xtw, 45xcbgji
    if re.fullmatch(r"[a-z0-9]{6,12}", s) and re.search(r"[a-z]", s) and re.search(r"\d", s):
        return True

    # Hash-like folders
    if re.fullmatch(r"[a-f0-9]{8,64}", s):
        return True

    # MSI/temp folders such as msi9f5f.tmp-0 or abc123.tmp-0
    if re.fullmatch(r".*\.tmp(?:-\d+)?", s):
        return True

    # Common version folders
    if re.fullmatch(r"\d+(?:\.\d+){1,5}", s):
        return True

    return False


def wildcard_for_volatile_segment(segment: str) -> str:
    s = (segment or "").lower().strip()

    if re.fullmatch(r".*\.tmp(?:-\d+)?", s):
        # Preserve tmp suffix behavior without preserving the random prefix.
        suffix = s[s.find(".tmp"):]
        return "*" + suffix

    return "*"


def _compression_mode(settings: RuleSettings) -> str:
    mode = str(getattr(settings, "path_compression_mode", "balanced") or "balanced").lower().strip()
    if mode not in {"off", "conservative", "balanced", "aggressive"}:
        mode = "balanced"
    return mode


def _compression_min_group(settings: RuleSettings) -> int:
    mode = _compression_mode(settings)
    if mode == "aggressive":
        return max(2, int(getattr(settings, "min_compression_group_size", 3)) - 1)
    if mode == "conservative":
        return max(5, int(getattr(settings, "min_compression_group_size", 3)))
    return int(getattr(settings, "min_compression_group_size", 3))


def _compress_same_shape_paths(cleaned: List[str], settings: RuleSettings) -> Optional[str]:
    mode = _compression_mode(settings)
    if mode == "off":
        return None

    split_items = []
    for p in cleaned:
        root, segments, sep = split_path(p)
        if not root or not segments:
            continue
        split_items.append((root, segments, sep))

    if len(split_items) < _compression_min_group(settings):
        return None

    roots = {x[0] for x in split_items}
    if len(roots) != 1:
        return None

    lengths = {len(x[1]) for x in split_items}
    if len(lengths) != 1:
        return None

    root = split_items[0][0]
    sep = split_items[0][2]
    segment_matrix = [x[1] for x in split_items]
    depth = len(segment_matrix[0])

    compressed = []
    wildcard_count = 0
    changed_columns = 0

    for idx in range(depth):
        col = [segments[idx] for segments in segment_matrix]
        unique_vals = sorted(set(col))

        if len(unique_vals) == 1:
            compressed.append(unique_vals[0])
            continue

        unique_ratio = len(unique_vals) / max(1, len(col))
        all_volatile = all(is_volatile_path_segment(v) for v in unique_vals)

        should_wildcard = False
        if all_volatile:
            should_wildcard = True
        elif mode == "aggressive" and unique_ratio >= 0.65:
            should_wildcard = True
        elif mode == "balanced" and unique_ratio >= 0.80:
            should_wildcard = True
        elif mode == "conservative" and unique_ratio >= 0.95 and all_volatile:
            should_wildcard = True

        if should_wildcard:
            wildcard = wildcard_for_volatile_segment(unique_vals[0])
            compressed.append(wildcard)
            wildcard_count += wildcard.count("*")
            changed_columns += 1
        else:
            return None

    max_wc = int(getattr(settings, "max_compression_wildcards", getattr(settings, "max_wildcards", 2)))
    if wildcard_count == 0 or wildcard_count > max_wc:
        return None

    if changed_columns == 0:
        return None

    if root == "/":
        candidate = "/" + sep.join(compressed)
    else:
        candidate = sep.join([root] + compressed)

    return candidate if candidate.count("*") <= max_wc else None


def _path_family_key(path: str, settings: RuleSettings) -> Optional[Tuple[str, int, str]]:
    """
    Builds a shape key that groups sibling volatile paths together before final
    rule construction. Volatile segments are replaced with <VOLATILE>, stable
    segments are preserved.
    """
    p = normalize_path(path)
    if not p:
        return None

    root, segments, sep = split_path(p)
    if not root or not segments:
        return None

    shaped = []
    for segment in segments:
        if is_volatile_path_segment(segment):
            shaped.append("<VOLATILE>")
        else:
            shaped.append(segment)

    return (root, len(segments), sep.join(shaped))


def compress_similar_paths(paths: List[str], settings: RuleSettings) -> Optional[str]:
    """
    Compress repetitive path families by wildcarding volatile middle folders while
    preserving stable prefix and filename/leaf where possible.

    This is mode-aware:
      conservative = only strong volatile same-shape groups
      balanced     = volatile plus high-cardinality same-shape groups
      aggressive   = broader path-only family compression
    """
    if not getattr(settings, "enable_path_compression", True):
        return None
    if _compression_mode(settings) == "off":
        return None

    cleaned = sorted({normalize_path(p) for p in paths if normalize_path(p)})
    min_group = _compression_min_group(settings)

    if len(cleaned) < min_group:
        return None

    # First try full input if it is already same-shape.
    direct = _compress_same_shape_paths(cleaned, settings)
    if direct:
        return direct

    # Then group by shape/family so mixed-depth paths do not prevent compression.
    by_family: Dict[Tuple[str, int, str], List[str]] = {}
    by_len: Dict[int, List[str]] = {}

    for p in cleaned:
        fam = _path_family_key(p, settings)
        if fam:
            by_family.setdefault(fam, []).append(p)
        root, segments, _sep = split_path(p)
        if root and segments:
            by_len.setdefault(len(segments), []).append(p)

    candidates: List[Tuple[int, int, str]] = []

    for _family, group in by_family.items():
        if len(group) < min_group:
            continue
        compressed = _compress_same_shape_paths(group, settings)
        if compressed:
            candidates.append((len(group), -len(compressed), compressed))

    # Fallback same-depth compression for cases where volatile detection misses
    # but the column uniqueness pattern is obvious.
    for _length, group in by_len.items():
        if len(group) < min_group:
            continue
        compressed = _compress_same_shape_paths(group, settings)
        if compressed:
            candidates.append((len(group), -len(compressed), compressed))

    if candidates:
        candidates.sort(reverse=True)
        return candidates[0][2]

    ext_candidate = extension_family_candidate(cleaned, settings)
    if ext_candidate:
        return ext_candidate

    return None


def compress_path_families_global(rules_df: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    """
    Performs a global path-only compression pass before strict final export.

    Conservative mode only runs inside the normal condition groups.
    Balanced/Aggressive can add path-only family rules even when Certificate,
    Process Path, or Created By differ across rows. This is what reduces large
    Tanium-style temp-folder exports.
    """
    if rules_df.empty or not getattr(settings, "enable_path_compression", True):
        return rules_df

    mode = _compression_mode(settings)
    if mode in {"off", "conservative"}:
        return rules_df

    if "Path" not in rules_df.columns:
        return rules_df

    paths = [p for p in rules_df["Path"].dropna().astype(str).tolist() if p.strip()]
    if not paths:
        return rules_df

    cleaned = sorted({normalize_path(p) for p in paths if normalize_path(p)})
    min_group = _compression_min_group(settings)
    by_family: Dict[Tuple[str, int, str], List[str]] = {}

    for p in cleaned:
        fam = _path_family_key(p, settings)
        if fam:
            by_family.setdefault(fam, []).append(p)

    compression_rows = []
    global_ext_candidate = extension_family_candidate(cleaned, settings)
    if global_ext_candidate:
        row = {col: None for col in rules_df.columns}
        row["Path"] = global_ext_candidate
        compression_rows.append(row)
        for idx, path in rules_df["Path"].dropna().astype(str).items():
            if path != global_ext_candidate and wildcard_pattern_matches_path(global_ext_candidate, path):
                covered_indexes.add(idx)
    covered_indexes = set()

    for _fam, group_paths in by_family.items():
        if len(group_paths) < min_group:
            continue

        compressed = _compress_same_shape_paths(group_paths, settings)
        if not compressed:
            continue

        # Create a path-only rule so varying process/cert/created-by values do not
        # prevent reduction of obvious path families.
        row = {col: None for col in rules_df.columns}
        row["Path"] = compressed
        compression_rows.append(row)

        for idx, path in rules_df["Path"].dropna().astype(str).items():
            if path != compressed and wildcard_pattern_matches_path(compressed, path):
                covered_indexes.add(idx)

    if covered_indexes:
        rules_df = rules_df.drop(index=list(covered_indexes), errors="ignore")

    if compression_rows:
        rules_df = pd.concat([rules_df, pd.DataFrame(compression_rows)], ignore_index=True)

    return rules_df


def wildcard_pattern_matches_path(pattern: str, path: str) -> bool:
    pattern_norm = normalize_path(pattern) or ""
    path_norm = normalize_path(path) or ""
    if not pattern_norm or not path_norm:
        return False
    escaped = re.escape(pattern_norm).replace(r"\*", ".*")
    return re.fullmatch(escaped, path_norm, flags=re.IGNORECASE) is not None


def compress_final_rules(rules_df: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    """
    Adds compressed path rules where multiple rows share the same non-path conditions.
    Removes the specific path rows covered by the compressed path when safe so the
    final output is shorter.
    """
    if rules_df.empty or not getattr(settings, "enable_path_compression", True):
        return rules_df

    if "Path" not in rules_df.columns:
        return rules_df

    compression_rows = []
    covered_indexes = set()
    group_cols = [c for c in ["Certificate", "Process Path", "Created By"] if c in rules_df.columns]

    grouped = [((), rules_df)] if not group_cols else rules_df.groupby(group_cols, dropna=False)

    for keys, section in grouped:
        paths = [p for p in section["Path"].dropna().astype(str).tolist() if p.strip()]
        compressed = compress_similar_paths(paths, settings)
        if not compressed:
            continue

        row = {col: None for col in rules_df.columns}
        row["Path"] = compressed

        if group_cols:
            if not isinstance(keys, tuple):
                keys = (keys,)
            for col, value in zip(group_cols, keys):
                row[col] = normalize_spaces(value)

        compression_rows.append(row)

        for idx, path in section["Path"].dropna().astype(str).items():
            if path != compressed and wildcard_pattern_matches_path(compressed, path):
                covered_indexes.add(idx)

    if covered_indexes:
        rules_df = rules_df.drop(index=list(covered_indexes), errors="ignore")

    if compression_rows:
        rules_df = pd.concat([rules_df, pd.DataFrame(compression_rows)], ignore_index=True)

    return rules_df


def build_final_rules(candidate_pairs: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    if candidate_pairs.empty:
        return pd.DataFrame(columns=["Rule Name", "Rule Type", "Path", "Process Path", "Certificate", "Created By", "Source Rows", "Weighted Count", "Condition Count", "Wildcard Count", "Aggressiveness"])

    rules: List[Dict[str, object]] = []
    for _, p in candidate_pairs.iterrows():
        pair_type = p["PairType"]
        rule = {"Path": None, "Process Path": None, "Certificate": None, "Created By": None}
        if pair_type == "ProcessPath":
            rule["Process Path"] = p["Condition1WC"] if p["Condition1Kind"] == "Process Path" else p["Condition2WC"]
            rule["Path"] = p["Condition1WC"] if p["Condition1Kind"] == "Path" else p["Condition2WC"]
        elif pair_type == "ProcessCert":
            rule["Process Path"] = p["Condition1WC"] if p["Condition1Kind"] == "Process Path" else p["Condition2WC"]
            rule["Certificate"] = p["Condition1Key"] if p["Condition1Kind"] == "Certificate" else p["Condition2Key"]
        elif pair_type == "PathCert":
            rule["Path"] = p["Condition1WC"] if p["Condition1Kind"] == "Path" else p["Condition2WC"]
            rule["Certificate"] = p["Condition1Key"] if p["Condition1Kind"] == "Certificate" else p["Condition2Key"]
        elif pair_type == "PathCreatedBy":
            rule["Path"] = p["Condition1WC"] if p["Condition1Kind"] == "Path" else p["Condition2WC"]
            rule["Created By"] = p["Condition1Key"] if p["Condition1Kind"] == "Created By" else p["Condition2Key"]
        elif pair_type == "ProcessCreatedBy":
            rule["Process Path"] = p["Condition1WC"] if p["Condition1Kind"] == "Process Path" else p["Condition2WC"]
            rule["Created By"] = p["Condition1Key"] if p["Condition1Kind"] == "Created By" else p["Condition2Key"]
        rule["Rule Type"] = pair_type
        rule["Source Rows"] = int(p["Occurrences"])
        rule["Weighted Count"] = int(p.get("Weighted Count", p["Occurrences"]))
        rule["Condition Count"] = count_rule_conditions(rule)
        rule["Wildcard Count"] = ((rule.get("Path") or "").count("*") + (rule.get("Process Path") or "").count("*"))
        rule["Aggressiveness"] = "derived"
        rule["Example Paths"] = p.get("ExamplePaths")
        rule["Example Processes"] = p.get("ExampleProcesses")
        rule["Example Certificates"] = p.get("Example Certificates")
        rule["Example Created By"] = p.get("Example Created By")
        rule["Example Notes"] = p.get("ExampleNotes")
        rules.append(rule)

    rules_df = pd.DataFrame(rules)
    rules_df = enforce_high_risk_process_rules(rules_df, settings)
    rules_df = rules_df[rules_df["Source Rows"] >= settings.min_source_rows].copy()
    rules_df = rules_df[rules_df["Condition Count"] >= 2].copy()
    rules_df = rules_df[rules_df["Wildcard Count"] <= settings.max_wildcards].copy()
    if settings.require_path:
        rules_df = rules_df[rules_df["Path"].notna() & (rules_df["Path"] != "")].copy()

    if settings.merge_sibling_paths and getattr(settings, "enable_rule_merging", True) and not rules_df.empty:
        merged_rows = []
        group_keys = ["Process Path", "Certificate", "Created By"]
        for keys, section in rules_df.groupby(group_keys, dropna=False):
            exact_paths = []
            for blob in section["Example Paths"].fillna(""):
                exact_paths.extend([line.strip() for line in str(blob).splitlines() if line.strip()])
            merged = cluster_to_wildcards(exact_paths, settings)
            if not merged:
                continue
            merged_rule = {
                "Path": merged,
                "Process Path": normalize_spaces(keys[0]),
                "Certificate": normalize_spaces(keys[1]),
                "Created By": normalize_spaces(keys[2]),
                "Rule Type": "MergedPathGroup",
                "Source Rows": int(section["Source Rows"].sum()),
                "Weighted Count": int(section["Weighted Count"].sum()) if "Weighted Count" in section.columns else int(section["Source Rows"].sum()),
                "Example Paths": "\n".join(sorted(set(exact_paths))[:12]),
                "Example Processes": "\n".join(sorted(set([x for blob in section["Example Processes"].fillna("") for x in str(blob).splitlines() if x.strip()]))[:12]),
                "Example Notes": "\n---\n".join(section["Example Notes"].head(2).astype(str).tolist()),
                "Aggressiveness": "merged",
            }
            merged_rule["Condition Count"] = count_rule_conditions(merged_rule)
            merged_rule["Wildcard Count"] = ((merged_rule.get("Path") or "").count("*") + (merged_rule.get("Process Path") or "").count("*"))
            if merged_rule["Condition Count"] >= 2 and merged_rule["Wildcard Count"] <= settings.max_wildcards:
                merged_rows.append(merged_rule)
        if merged_rows:
            rules_df = pd.concat([rules_df, pd.DataFrame(merged_rows)], ignore_index=True)

    rules_df = enforce_high_risk_process_rules(rules_df, settings)
    rules_df = rules_df.drop_duplicates(subset=["Path", "Process Path", "Certificate", "Created By", "Rule Type"], keep="first")
    rules_df = rules_df.sort_values(by=["Weighted Count", "Source Rows", "Condition Count", "Wildcard Count", "Rule Type"], ascending=[False, False, False, True, True]).reset_index(drop=True)

    # Strict final export schema for ThreatLocker application policy creation.
    # Metadata remains available in Candidate Pairs / Rule Pair Export, but not here.
    rules_df = compress_final_rules(rules_df, settings)
    rules_df = compress_path_families_global(rules_df, settings)
    rules_df = enforce_high_risk_process_rules(rules_df, settings)

    final_columns = ["Path", "Certificate", "Process Path", "Created By"]
    for col in final_columns:
        if col not in rules_df.columns:
            rules_df[col] = None

    rules_df = rules_df[final_columns].copy()
    rules_df = normalize_final_rule_certificates(rules_df)
    rules_df = rules_df.drop_duplicates().dropna(how="all").reset_index(drop=True)
    return rules_df


def build_pair_export(candidate_pairs: pd.DataFrame) -> pd.DataFrame:
    if candidate_pairs.empty:
        return pd.DataFrame(columns=["Pair Name", "Pair Type", "Path", "Process Path", "Certificate", "Created By", "Weighted Count", "Occurrences"])
    rows = []
    for _, p in candidate_pairs.iterrows():
        pair_type = p["PairType"]
        row = {"Path": None, "Process Path": None, "Certificate": None, "Created By": None}
        if pair_type == "ProcessPath":
            row["Process Path"] = p["Condition1WC"] if p["Condition1Kind"] == "Process Path" else p["Condition2WC"]
            row["Path"] = p["Condition1WC"] if p["Condition1Kind"] == "Path" else p["Condition2WC"]
        elif pair_type == "ProcessCert":
            row["Process Path"] = p["Condition1WC"] if p["Condition1Kind"] == "Process Path" else p["Condition2WC"]
            row["Certificate"] = p["Condition1Key"] if p["Condition1Kind"] == "Certificate" else p["Condition2Key"]
        elif pair_type == "PathCert":
            row["Path"] = p["Condition1WC"] if p["Condition1Kind"] == "Path" else p["Condition2WC"]
            row["Certificate"] = p["Condition1Key"] if p["Condition1Kind"] == "Certificate" else p["Condition2Key"]
        elif pair_type == "PathCreatedBy":
            row["Path"] = p["Condition1WC"] if p["Condition1Kind"] == "Path" else p["Condition2WC"]
            row["Created By"] = p["Condition1Key"] if p["Condition1Kind"] == "Created By" else p["Condition2Key"]
        elif pair_type == "ProcessCreatedBy":
            row["Process Path"] = p["Condition1WC"] if p["Condition1Kind"] == "Process Path" else p["Condition2WC"]
            row["Created By"] = p["Condition1Key"] if p["Condition1Kind"] == "Created By" else p["Condition2Key"]
        row["Pair Type"] = pair_type
        row["Weighted Count"] = int(p.get("Weighted Count", p["Occurrences"]))
        row["Occurrences"] = int(p["Occurrences"])
        row["Example Paths"] = p.get("ExamplePaths")
        row["Example Processes"] = p.get("ExampleProcesses")
        rows.append(row)
    pair_df = pd.DataFrame(rows)
    pair_df.insert(0, "Pair Name", [f"TL Pair {i+1:04d}" for i in range(len(pair_df))])
    return pair_df.sort_values(["Weighted Count", "Occurrences"], ascending=[False, False]).reset_index(drop=True)


def build_outputs(df: pd.DataFrame, settings: RuleSettings) -> Dict[str, pd.DataFrame]:
    parsed = apply_parsing(df)
    combined_review = parsed[[c for c in ["path", "process_path", "certificate_primary", "created_by", "sha256_hash", "md5_hash", "hostname", "timestamp_utc", "count", "Notes"] if c in parsed.columns]].copy()
    combined_review.columns = [
        "Path" if c == "path" else
        "Process Path" if c == "process_path" else
        "Certificate" if c == "certificate_primary" else
        "Created By" if c == "created_by" else
        "SHA256" if c == "sha256_hash" else
        "MD5" if c == "md5_hash" else
        "Host Name" if c == "hostname" else
        "Timestamp" if c == "timestamp_utc" else
        "Count" if c == "count" else c
        for c in combined_review.columns
    ]
    detailed = build_candidate_pairs(parsed, settings)
    rule_pairs_export = build_pair_export(detailed)
    final_rules = build_final_rules(detailed, settings)
    return {
        "parsed": parsed,
        "combined_review": combined_review,
        "candidate_rule_pairs": detailed,
        "rule_pairs_export": rule_pairs_export,
        "final_rules": final_rules,
    }


def dataframe_to_csv_bytes(df: pd.DataFrame) -> bytes:
    buffer = io.StringIO()
    df.to_csv(buffer, index=False)
    return buffer.getvalue().encode("utf-8")

# ============================================================
# v2 Optimizer Overrides - risk-aware + smarter compression
# ============================================================
# These definitions intentionally override earlier functions while keeping the
# original parser helpers available. They add:
#   - embedded multi-path splitting
#   - language/locale folder compression
#   - stronger version/volatile folder wildcarding
#   - high-risk/LOLBin Process Path 3-condition enforcement
#   - certificate-first anchor rules and covered-rule suppression

LANGUAGE_FOLDERS = {
    "en-us", "en-gb", "en", "fr-fr", "fr", "de-de", "de", "es-es", "es", "it-it", "it",
    "ja-jp", "ja", "ko-kr", "ko", "pt-br", "pt", "ru-ru", "ru", "zh-cn", "zh-tw",
    "zh-hans", "zh-hant", "cs-cz", "cs", "hu-hu", "hu", "pl-pl", "pl", "tr-tr", "tr",
    "nl-nl", "nl", "sv-se", "sv", "da-dk", "da", "fi-fi", "fi", "nb-no", "no"
}

# Save earlier implementations where useful.
_base_apply_parsing = apply_parsing
_base_build_final_rules = build_final_rules
_base_collapse_version_segments = collapse_version_segments
_base_is_volatile_path_segment = is_volatile_path_segment
_base_compress_final_rules = compress_final_rules
_base_compress_path_families_global = compress_path_families_global


def split_embedded_paths(value: Optional[str]) -> List[str]:
    """Split a cell that accidentally contains multiple Windows/Unix paths."""
    text = normalize_spaces(value)
    if not text:
        return []
    # Normalize obvious separators first, but preserve spaces inside paths.
    raw = str(text).strip().strip('"')
    starts = [m.start() for m in re.finditer(r"(?i)(?:[a-z]:\\|/[^/\s])", raw)]
    if len(starts) <= 1:
        p = normalize_path(raw)
        return [p] if p else []
    parts: List[str] = []
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(raw)
        part = raw[start:end].strip().strip('"').strip(";,|")
        # Remove trailing text that is unlikely to be part of the path.
        part = re.sub(r"\s+(?:Path:|Process:|Cert:|Certificate:|Hash:).*$", "", part, flags=re.IGNORECASE).strip()
        p = normalize_path(part)
        if p:
            parts.append(p)
    return list(dict.fromkeys(parts))


def has_embedded_multiple_paths(value: Optional[str]) -> bool:
    return len(split_embedded_paths(value)) > 1


def explode_embedded_path_rows(df: pd.DataFrame) -> pd.DataFrame:
    """Explode rows where Path contains multiple embedded paths into one row per path."""
    if df.empty:
        return df
    working = df.copy()
    working.columns = [str(c).strip() for c in working.columns]
    working = _rename_known_columns(working)
    path_col = "path" if "path" in working.columns else None
    if not path_col:
        return df

    rows: List[Dict[str, object]] = []
    for _, row in working.iterrows():
        row_dict = row.to_dict()
        paths = split_embedded_paths(row_dict.get(path_col))
        if len(paths) <= 1:
            rows.append(row_dict)
            continue
        for p in paths:
            new_row = dict(row_dict)
            new_row[path_col] = p
            rows.append(new_row)
    return pd.DataFrame(rows, columns=working.columns)


def collapse_version_segments(path: str) -> str:
    """Collapse version, locale, GUID, and volatile installer segments earlier in the pipeline."""
    sep = "\\" if "\\" in path else "/"
    segments = path.split(sep)
    for i, segment in enumerate(segments):
        s = (segment or "").lower().strip()
        if not s:
            continue
        if s in LANGUAGE_FOLDERS:
            segments[i] = "*"
        elif re.fullmatch(r"v?\d+(?:\.\d+){1,8}", s, flags=re.IGNORECASE):
            segments[i] = "*"
        elif re.fullmatch(r"r\d{1,3}", s, flags=re.IGNORECASE):
            segments[i] = "*"
        elif re.fullmatch(r"20\d{2}", s):
            segments[i] = "*"
        elif re.fullmatch(r"\{?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}?", s):
            segments[i] = "*"
        elif re.fullmatch(r"\d{10,}", s):
            segments[i] = "*"
        elif re.fullmatch(r"[a-f0-9]{16,64}", s):
            segments[i] = "*"
    return sep.join(segments)


# Clear cached conversion because collapse_version_segments changed.
try:
    _convert_to_normalized_path_cached.cache_clear()
except Exception:
    pass


def is_volatile_path_segment(segment: Optional[str]) -> bool:
    s = (normalize_spaces(segment) or "").lower().strip()
    if not s or s == "*":
        return False
    if s in LANGUAGE_FOLDERS:
        return True
    if re.fullmatch(r"v?\d+(?:\.\d+){1,8}", s, flags=re.IGNORECASE):
        return True
    if re.fullmatch(r"r\d{1,3}", s, flags=re.IGNORECASE):
        return True
    if re.fullmatch(r"20\d{2}", s):
        return True
    return _base_is_volatile_path_segment(segment)


def get_common_prefix_path(paths: List[str], stop_before_volatile: bool = True) -> Optional[str]:
    cleaned = [normalize_path(p) for p in paths if normalize_path(p)]
    if not cleaned:
        return None
    parsed = [split_path(p) for p in cleaned]
    roots = {x[0] for x in parsed}
    seps = {x[2] for x in parsed}
    if len(roots) != 1 or len(seps) != 1:
        return None
    root = parsed[0][0]
    sep = parsed[0][2]
    segment_lists = [x[1] for x in parsed]
    common: List[str] = []
    for segment_group in zip(*segment_lists):
        lowered = {s.lower() for s in segment_group}
        if len(lowered) != 1:
            break
        candidate = segment_group[0]
        if stop_before_volatile and is_volatile_path_segment(candidate):
            break
        common.append(candidate)
    if not common:
        return None
    if root == "/":
        return "/" + sep.join(common)
    return sep.join([root] + common)


def compress_language_folder_families(rules_df: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    """Collapse repeated locale-specific subfolders to a common parent wildcard."""
    if rules_df.empty or "Path" not in rules_df.columns:
        return rules_df
    group_cols = [c for c in ["Certificate", "Process Path", "Created By"] if c in rules_df.columns]
    output = rules_df.copy()
    rows_to_add: List[Dict[str, object]] = []
    indexes_to_drop = set()
    grouped = [((), output)] if not group_cols else output.groupby(group_cols, dropna=False)
    for keys, section in grouped:
        paths = [normalize_path(p) for p in section["Path"].dropna().astype(str).tolist() if normalize_path(p)]
        if len(paths) < 3:
            continue
        locale_paths = []
        for p in paths:
            _root, segs, _sep = split_path(p)
            if any(seg.lower() in LANGUAGE_FOLDERS for seg in segs):
                locale_paths.append(p)
        if len(locale_paths) < 3:
            continue
        prefix = get_common_prefix_path(locale_paths, stop_before_volatile=True)
        if not prefix:
            continue
        candidate = prefix.rstrip("\\/") + ("\\" if "\\" in prefix else "/") + "*"
        if candidate.count("*") > getattr(settings, "max_compression_wildcards", settings.max_wildcards):
            continue
        row = {col: None for col in output.columns}
        row["Path"] = candidate
        if group_cols:
            if not isinstance(keys, tuple):
                keys = (keys,)
            for col, value in zip(group_cols, keys):
                row[col] = normalize_spaces(value)
        if "Rule Type" in row:
            row["Rule Type"] = "LanguageFolderFamily"
        rows_to_add.append(row)
        for idx, path in section["Path"].dropna().astype(str).items():
            if wildcard_pattern_matches_path(candidate, path):
                indexes_to_drop.add(idx)
    if indexes_to_drop:
        output = output.drop(index=list(indexes_to_drop), errors="ignore")
    if rows_to_add:
        output = pd.concat([output, pd.DataFrame(rows_to_add)], ignore_index=True)
    return output


def compress_extension_families_global(rules_df: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    """Add *.dll / *.exe family rules when many files share the same stable vendor/product anchor."""
    if rules_df.empty or "Path" not in rules_df.columns or not getattr(settings, "enable_extension_family_compression", True):
        return rules_df
    group_cols = [c for c in ["Certificate", "Process Path", "Created By"] if c in rules_df.columns]
    output = rules_df.copy()
    rows_to_add: List[Dict[str, object]] = []
    indexes_to_drop = set()
    grouped = [((), output)] if not group_cols else output.groupby(group_cols, dropna=False)
    for keys, section in grouped:
        paths = [normalize_path(p) for p in section["Path"].dropna().astype(str).tolist() if normalize_path(p)]
        candidate = extension_family_candidate(paths, settings)
        if not candidate:
            continue
        row = {col: None for col in output.columns}
        row["Path"] = candidate
        if group_cols:
            if not isinstance(keys, tuple):
                keys = (keys,)
            for col, value in zip(group_cols, keys):
                row[col] = normalize_spaces(value)
        if "Rule Type" in row:
            row["Rule Type"] = "ExtensionFamily"
        rows_to_add.append(row)
        for idx, path in section["Path"].dropna().astype(str).items():
            if wildcard_pattern_matches_path(candidate, path):
                indexes_to_drop.add(idx)
    if indexes_to_drop:
        output = output.drop(index=list(indexes_to_drop), errors="ignore")
    if rows_to_add:
        output = pd.concat([output, pd.DataFrame(rows_to_add)], ignore_index=True)
    return output


def add_certificate_anchor_rules(rules_df: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    """Add broad but still certificate-scoped rules, then let covered-rule suppression remove duplicates."""
    if rules_df.empty or "Path" not in rules_df.columns or "Certificate" not in rules_df.columns:
        return rules_df
    min_group = max(3, int(getattr(settings, "min_compression_group_size", 3)))
    rows_to_add: List[Dict[str, object]] = []
    for cert, section in rules_df.groupby("Certificate", dropna=True):
        cert = normalize_spaces(cert)
        if not cert:
            continue
        paths = [normalize_path(p) for p in section["Path"].dropna().astype(str).tolist() if normalize_path(p)]
        if len(paths) < min_group:
            continue
        # Prefer vendor/product anchors: Program Files\Vendor\*, ProgramData\Vendor\*, Users\*\...\Vendor\*
        prefix = get_common_prefix_path(paths, stop_before_volatile=True)
        if not prefix:
            continue
        root, segs, sep = split_path(prefix)
        if not segs:
            continue
        # Avoid overly broad c:\program files\*; require at least vendor depth.
        lowered = [s.lower() for s in segs]
        min_depth = 2 if lowered and lowered[0] in {"program files", "program files (x86)", "programdata"} else 3
        if len(segs) < min_depth:
            continue
        candidate = prefix.rstrip(sep) + sep + "*"
        if candidate.count("*") > getattr(settings, "max_compression_wildcards", settings.max_wildcards):
            continue
        row = {col: None for col in rules_df.columns}
        row["Path"] = candidate
        row["Certificate"] = cert
        if "Rule Type" in row:
            row["Rule Type"] = "CertificateAnchor"
        rows_to_add.append(row)
    if rows_to_add:
        return pd.concat([rules_df, pd.DataFrame(rows_to_add)], ignore_index=True)
    return rules_df


def rule_is_covered(broad: Dict[str, object], narrow: Dict[str, object]) -> bool:
    """Return True when broad rule covers narrow rule and is not less restrictive on other conditions."""
    broad_path = normalize_spaces(broad.get("Path"))
    narrow_path = normalize_spaces(narrow.get("Path"))
    if not broad_path or not narrow_path or broad_path == narrow_path:
        return False
    if not wildcard_pattern_matches_path(broad_path, narrow_path):
        return False
    for col in ["Certificate", "Process Path", "Created By"]:
        b = normalize_spaces(broad.get(col))
        n = normalize_spaces(narrow.get(col))
        # If the broad rule has a condition, narrow must have same condition to be covered.
        if b and b != n:
            return False
        # If broad does not have a condition, it is less restrictive; do not suppress a narrower rule with additional constraints.
        if not b and n:
            return False
    return True


def suppress_covered_rules(rules_df: pd.DataFrame) -> pd.DataFrame:
    if rules_df.empty or "Path" not in rules_df.columns:
        return rules_df
    df = rules_df.copy().reset_index(drop=True)
    drop_indexes = set()
    records = df.to_dict("records")
    for i, broad in enumerate(records):
        broad_conditions = count_rule_conditions(broad)
        broad_wc = (normalize_spaces(broad.get("Path")) or "").count("*")
        for j, narrow in enumerate(records):
            if i == j or j in drop_indexes:
                continue
            if count_rule_conditions(narrow) < broad_conditions:
                continue
            if rule_is_covered(broad, narrow):
                # Prefer broader path if condition count is equal or broad has stronger/equal non-path conditions.
                drop_indexes.add(j)
    if drop_indexes:
        df = df.drop(index=list(drop_indexes), errors="ignore")
    return df.reset_index(drop=True)


def apply_parsing(df: pd.DataFrame) -> pd.DataFrame:
    exploded = explode_embedded_path_rows(df)
    parsed = _base_apply_parsing(exploded)
    # One more split pass after parsing in case path was extracted from Notes as a multi-path blob.
    if "path" in parsed.columns:
        rows: List[Dict[str, object]] = []
        for _, row in parsed.iterrows():
            row_dict = row.to_dict()
            paths = split_embedded_paths(row_dict.get("path"))
            if len(paths) <= 1:
                rows.append(row_dict)
            else:
                for p in paths:
                    new_row = dict(row_dict)
                    new_row["path"] = p
                    new_row["wildcard_path"] = shorten_leaf(p)
                    rows.append(new_row)
        parsed = pd.DataFrame(rows)
    if "row_fingerprint" in parsed.columns:
        parsed["row_fingerprint"] = parsed.apply(
            lambda row: " | ".join([
                normalize_spaces(row.get("path")) or "",
                normalize_spaces(row.get("process_path")) or "",
                normalize_spaces(row.get("certificate_primary")) or "",
                normalize_spaces(row.get("created_by")) or "",
                normalize_spaces(row.get("sha256_hash")) or normalize_spaces(row.get("md5_hash")) or "",
            ]), axis=1
        )
    return parsed


def compress_final_rules(rules_df: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    result = _base_compress_final_rules(rules_df, settings)
    result = compress_language_folder_families(result, settings)
    result = compress_extension_families_global(result, settings)
    return result


def compress_path_families_global(rules_df: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    result = _base_compress_path_families_global(rules_df, settings)
    result = compress_language_folder_families(result, settings)
    result = compress_extension_families_global(result, settings)
    return result


def build_final_rules(candidate_pairs: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    if candidate_pairs.empty:
        return pd.DataFrame(columns=["Path", "Certificate", "Process Path", "Created By"])
    # Use the original builder first, then perform security-aware post-processing.
    rules_df = _base_build_final_rules(candidate_pairs, settings)
    if rules_df.empty:
        return rules_df

    # Add metadata back if original final export stripped it; later we strip again.
    for col in ["Path", "Certificate", "Process Path", "Created By"]:
        if col not in rules_df.columns:
            rules_df[col] = None

    # Re-run compression passes on the strict schema.
    rules_df = add_certificate_anchor_rules(rules_df, settings)
    rules_df = compress_language_folder_families(rules_df, settings)
    rules_df = compress_extension_families_global(rules_df, settings)
    rules_df = suppress_covered_rules(rules_df)

    # High-risk process enforcement should happen after compression so broad high-risk process rules are removed
    # unless they still contain at least Path + Process Path + Certificate/Created By.
    rules_df = enforce_high_risk_process_rules(rules_df, settings)

    final_columns = ["Path", "Certificate", "Process Path", "Created By"]
    for col in final_columns:
        if col not in rules_df.columns:
            rules_df[col] = None
    rules_df = rules_df[final_columns].copy()
    rules_df = normalize_final_rule_certificates(rules_df)
    rules_df = rules_df.drop_duplicates().dropna(how="all").reset_index(drop=True)
    return rules_df


def build_outputs(df: pd.DataFrame, settings: RuleSettings) -> Dict[str, pd.DataFrame]:
    parsed = apply_parsing(df)
    combined_review = parsed[[c for c in ["path", "process_path", "certificate_primary", "created_by", "sha256_hash", "md5_hash", "hostname", "timestamp_utc", "count", "Notes"] if c in parsed.columns]].copy()
    combined_review.columns = [
        "Path" if c == "path" else
        "Process Path" if c == "process_path" else
        "Certificate" if c == "certificate_primary" else
        "Created By" if c == "created_by" else
        "SHA256" if c == "sha256_hash" else
        "MD5" if c == "md5_hash" else
        "Host Name" if c == "hostname" else
        "Timestamp" if c == "timestamp_utc" else
        "Count" if c == "count" else c
        for c in combined_review.columns
    ]
    detailed = build_candidate_pairs(parsed, settings)
    rule_pairs_export = build_pair_export(detailed)
    final_rules = build_final_rules(detailed, settings)
    return {
        "parsed": parsed,
        "combined_review": combined_review,
        "candidate_rule_pairs": detailed,
        "rule_pairs_export": rule_pairs_export,
        "final_rules": final_rules,
    }

# ============================================================
# v3 Optimizer Overrides - multi-path hardening + risk gates
# ============================================================
# This block overrides the v2 overrides above. It addresses observed Autodesk
# output issues:
#   - reliably splits concatenated Path cells before rule generation
#   - normalizes common certificate/vendor name variants
#   - rejects or downgrades dangerous user-writable wildcard rules
#   - enforces 3-condition minimum for LOLBins / high-risk process paths
#   - adds risk/coverage review output without changing the strict final CSV schema

WINDOWS_PATH_START_PATTERN = re.compile(r"(?i)(?=[a-z]:\\)")
WINDOWS_PATH_ANY_PATTERN = re.compile(r"(?i)[a-z]:\\")
USER_WRITABLE_PREFIXES = (
    r"c:\\users\\",
    r"c:\\windows\\temp\\",
    r"c:\\temp\\",
    r"c:\\programdata\\",
)
DANGEROUS_USER_PATH_PATTERNS = (
    re.compile(r"(?i)^c:\\users\\\*\\\*$"),
    re.compile(r"(?i)^c:\\users\\\*\.dll$"),
    re.compile(r"(?i)^c:\\users\\\*\.exe$"),
    re.compile(r"(?i)^c:\\users\\.*\\\*$"),
)

CERT_VENDOR_NORMALIZATION = {
    "developer express incorporated": "developer express",
    "developer express inc.": "developer express",
    "developer express inc": "developer express",
    "autodesk, inc.": "autodesk",
    "autodesk inc.": "autodesk",
    "autodesk inc": "autodesk",
    "portswigger ltd": "portswigger",
    "google llc": "google llc",
    "microsoft corporation": "microsoft corporation",
    "3dconnexion s.a.m.": "3dconnexion s.a.m.",
    "3dconnexion s.a.m": "3dconnexion s.a.m.",
}


def extract_windows_paths_from_blob(value: Optional[str]) -> List[str]:
    """Extract every Windows path from a blob while preserving spaces inside folder names."""
    if value is None:
        return []
    raw = str(value).replace("\r", "\n")
    raw = raw.strip().strip('"')
    if not raw or raw.lower() in {"nan", "none", "[]", "{}"}:
        return []

    starts = [m.start() for m in WINDOWS_PATH_ANY_PATTERN.finditer(raw)]
    if not starts:
        # Allow the original UNIX fallback for mac/linux exports.
        unix_hits = UNIX_PATH_PATTERN.findall(raw)
        return list(dict.fromkeys([normalize_path(x) for x in unix_hits if normalize_path(x)]))

    paths: List[str] = []
    for idx, start in enumerate(starts):
        end = starts[idx + 1] if idx + 1 < len(starts) else len(raw)
        part = raw[start:end]
        # Remove labels and table/csv residue after the path fragment.
        part = re.sub(r"(?is)\s+(?:Path|Process(?: Path)?|Certificate|Cert|Created By|Hash|Hostname):.*$", "", part)
        part = part.strip().strip('"').strip(";,|\t\n ")
        # When paths were separated by spaces, the prior slice may still contain a trailing delimiter.
        part = re.sub(r"\s+$", "", part)
        p = normalize_path(part)
        if p:
            paths.append(p)
    return list(dict.fromkeys(paths))


def split_embedded_paths(value: Optional[str]) -> List[str]:
    """Split a cell/blob into individual normalized paths. Overrides v2 splitter."""
    paths = extract_windows_paths_from_blob(value)
    if paths:
        return paths
    p = normalize_path(value)
    return [p] if p else []


def has_embedded_multiple_paths(value: Optional[str]) -> bool:
    return len(split_embedded_paths(value)) > 1


def normalize_certificate_vendor(value: Optional[str]) -> Optional[str]:
    cert = normalize_spaces(value)
    if not cert:
        return None
    cert = cert.strip().strip('"').strip("'")
    lowered = cert.lower().strip()
    # Prefer organization component when a full DN is present.
    org = re.search(r"(?:^|[,;|]\s*)o\s*=\s*([^,;|]+)", lowered, flags=re.IGNORECASE)
    if org:
        lowered = org.group(1).strip()
    cn = re.search(r"(?:^|[,;|]\s*)cn\s*=\s*([^,;|]+)", lowered, flags=re.IGNORECASE)
    if cn and not org:
        lowered = cn.group(1).strip()
    lowered = re.sub(r"\s+", " ", lowered).strip().strip('"')
    return CERT_VENDOR_NORMALIZATION.get(lowered, lowered)


def is_user_writable_path(path: Optional[str]) -> bool:
    p = normalize_path(path) or ""
    return any(p.startswith(prefix) for prefix in USER_WRITABLE_PREFIXES)


def is_dangerous_user_wildcard_rule(path: Optional[str]) -> bool:
    p = normalize_path(path) or ""
    if not p:
        return False
    if any(rx.fullmatch(p) for rx in DANGEROUS_USER_PATH_PATTERNS):
        return True
    # Very broad user-profile DLL/EXE wildcard without a stable product subfolder.
    if p.startswith(r"c:\\users\\") and "*" in p:
        leaf = p.rsplit("\\", 1)[-1]
        if leaf in {"*.dll", "*.exe", "*"}:
            return True
    return False


def rule_risk_score(row: Dict[str, object]) -> int:
    path = normalize_spaces(row.get("Path"))
    process = normalize_spaces(row.get("Process Path"))
    cert = normalize_spaces(row.get("Certificate"))
    created_by = normalize_spaces(row.get("Created By"))
    score = 0
    p = normalize_path(path) or ""
    if is_user_writable_path(p):
        score += 5
    if "\\temp\\" in p or "\\appdata\\local\\temp\\" in p:
        score += 5
    if process and is_high_risk_process_path(process):
        score += 5
    if (p.count("*") if p else 0) > 1:
        score += 3
    if not cert:
        score += 3
    if not process:
        score += 2
    if not created_by and is_user_writable_path(p):
        score += 2
    if is_dangerous_user_wildcard_rule(p):
        score += 10
    return score


def risk_label(score: int) -> str:
    if score >= 12:
        return "High"
    if score >= 6:
        return "Medium"
    return "Low"


def explode_embedded_path_rows(df: pd.DataFrame) -> pd.DataFrame:
    """Explode rows where Path contains multiple embedded paths into one row per path."""
    if df.empty:
        return df
    working = df.copy()
    working.columns = [str(c).strip() for c in working.columns]
    working = _rename_known_columns(working)
    path_col = "path" if "path" in working.columns else None
    if not path_col:
        return working

    rows: List[Dict[str, object]] = []
    for _, row in working.iterrows():
        row_dict = row.to_dict()
        paths = split_embedded_paths(row_dict.get(path_col))
        if len(paths) <= 1:
            if paths:
                row_dict[path_col] = paths[0]
            rows.append(row_dict)
            continue
        for p in paths:
            new_row = dict(row_dict)
            new_row[path_col] = p
            rows.append(new_row)
    return pd.DataFrame(rows)


def apply_parsing(df: pd.DataFrame) -> pd.DataFrame:
    exploded = explode_embedded_path_rows(df)
    parsed = _base_apply_parsing(exploded)

    # Split again after note parsing because Notes can populate parsed path with a multi-path blob.
    if "path" in parsed.columns:
        rows: List[Dict[str, object]] = []
        for _, row in parsed.iterrows():
            row_dict = row.to_dict()
            paths = split_embedded_paths(row_dict.get("path"))
            if len(paths) <= 1:
                if paths:
                    row_dict["path"] = paths[0]
                    row_dict["wildcard_path"] = shorten_leaf(paths[0])
                rows.append(row_dict)
            else:
                for p in paths:
                    new_row = dict(row_dict)
                    new_row["path"] = p
                    new_row["wildcard_path"] = shorten_leaf(p)
                    rows.append(new_row)
        parsed = pd.DataFrame(rows)

    # Normalize certificates before grouping so vendor variants collapse together.
    for col in ["certificate_primary", "certificate_raw", "certificate_all"]:
        if col in parsed.columns:
            parsed[col] = parsed[col].map(normalize_certificate_vendor)

    if "row_fingerprint" in parsed.columns:
        parsed["row_fingerprint"] = parsed.apply(
            lambda row: " | ".join([
                normalize_spaces(row.get("path")) or "",
                normalize_spaces(row.get("process_path")) or "",
                normalize_spaces(row.get("certificate_primary")) or "",
                normalize_spaces(row.get("created_by")) or "",
                normalize_spaces(row.get("sha256_hash")) or normalize_spaces(row.get("md5_hash")) or "",
            ]), axis=1
        )
    return parsed



def ensure_certificate_o_prefix(value: Optional[str]) -> Optional[str]:
    """Final export guard: ThreatLocker certificate rules must be stored as o=<vendor>."""
    cert = normalize_spaces(value)
    if not cert:
        return None

    cert = cert.strip().strip('"').strip("'")
    lowered = cert.lower().strip()

    org = re.search(r"(?:^|[,;|]\s*)o\s*=\s*([^,;|]+)", lowered, flags=re.IGNORECASE)
    if org:
        vendor = org.group(1).strip()
    else:
        cn = re.search(r"(?:^|[,;|]\s*)cn\s*=\s*([^,;|]+)", lowered, flags=re.IGNORECASE)
        vendor = cn.group(1).strip() if cn else lowered

    vendor = re.sub(r"^o\s*=\s*", "", vendor, flags=re.IGNORECASE).strip()
    vendor = CERT_VENDOR_NORMALIZATION.get(vendor, vendor)
    return f"o={vendor}" if vendor else None


def normalize_final_rule_certificates(rules_df: pd.DataFrame) -> pd.DataFrame:
    if rules_df.empty:
        return rules_df
    df = rules_df.copy()
    if "Certificate" in df.columns:
        df["Certificate"] = df["Certificate"].map(ensure_certificate_o_prefix)
    return df


def filter_dangerous_rules(rules_df: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    if rules_df.empty:
        return rules_df
    rows = []
    for _, row in rules_df.iterrows():
        rd = row.to_dict()
        path = normalize_spaces(rd.get("Path"))
        cond_count = count_rule_conditions(rd)
        # Block the worst generic user-writable wildcard rules entirely.
        if is_dangerous_user_wildcard_rule(path):
            continue
        # User-writable or temp executable content must have at least 3 conditions.
        if is_user_writable_path(path) and cond_count < 3:
            continue
        rows.append(rd)
    return pd.DataFrame(rows, columns=rules_df.columns if not rules_df.empty else None)


def extension_family_candidate(paths: List[str], settings: RuleSettings) -> Optional[str]:
    """Safer extension-family compression. Avoid generating Users\*.dll-style rules."""
    cleaned = sorted({normalize_path(p) for p in paths if normalize_path(p)})
    min_group = max(3, int(getattr(settings, "min_compression_group_size", 3)))
    if len(cleaned) < min_group:
        return None
    if any(is_user_writable_path(p) for p in cleaned):
        return None
    exts = {os.path.splitext(p)[1].lower() for p in cleaned if os.path.splitext(p)[1]}
    if len(exts) != 1:
        return None
    ext = next(iter(exts))
    if ext not in {".dll", ".exe", ".sys", ".jar"}:
        return None
    prefix = get_common_prefix_path(cleaned, stop_before_volatile=True)
    if not prefix:
        return None
    sep = "\\" if "\\" in prefix else "/"
    candidate = prefix.rstrip(sep) + sep + f"*{ext}"
    if is_dangerous_user_wildcard_rule(candidate):
        return None
    return candidate if candidate.count("*") <= getattr(settings, "max_compression_wildcards", settings.max_wildcards) else None


def add_certificate_anchor_rules(rules_df: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    """Add safe certificate-scoped vendor root rules; avoid user-writable anchors."""
    if rules_df.empty or "Path" not in rules_df.columns or "Certificate" not in rules_df.columns:
        return rules_df
    source = normalize_final_rule_certificates(rules_df)
    min_group = max(3, int(getattr(settings, "min_compression_group_size", 3)))
    rows_to_add: List[Dict[str, object]] = []
    for cert, section in source.groupby("Certificate", dropna=True):
        cert = normalize_certificate_vendor(cert)
        if not cert:
            continue
        paths = [normalize_path(p) for p in section["Path"].dropna().astype(str).tolist() if normalize_path(p)]
        paths = [p for p in paths if not is_user_writable_path(p)]
        if len(paths) < min_group:
            continue
        prefix = get_common_prefix_path(paths, stop_before_volatile=True)
        if not prefix:
            continue
        root, segs, sep = split_path(prefix)
        if not segs:
            continue
        lowered = [s.lower() for s in segs]
        min_depth = 2 if lowered and lowered[0] in {"program files", "program files (x86)", "programdata"} else 3
        if len(segs) < min_depth:
            continue
        candidate = prefix.rstrip(sep) + sep + "*"
        if is_dangerous_user_wildcard_rule(candidate):
            continue
        if candidate.count("*") > getattr(settings, "max_compression_wildcards", settings.max_wildcards):
            continue
        row = {col: None for col in source.columns}
        row["Path"] = candidate
        row["Certificate"] = cert
        if "Rule Type" in row:
            row["Rule Type"] = "CertificateAnchor"
        rows_to_add.append(row)
    if rows_to_add:
        return pd.concat([source, pd.DataFrame(rows_to_add)], ignore_index=True)
    return source


def enforce_high_risk_process_rules(rules_df: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    """Final gate: high-risk process path rules require at least 3 conditions."""
    if rules_df.empty or not getattr(settings, "enforce_high_risk_process_three_conditions", True):
        return rules_df
    min_conditions = int(getattr(settings, "high_risk_process_min_conditions", 3) or 3)
    rows = []
    for _, row in rules_df.iterrows():
        rd = row.to_dict()
        process_path = normalize_spaces(rd.get("Process Path"))
        if process_path and is_high_risk_process_path(process_path):
            if count_rule_conditions(rd) < min_conditions:
                continue
        rows.append(rd)
    return pd.DataFrame(rows, columns=rules_df.columns if not rules_df.empty else None)


def suppress_covered_rules(rules_df: pd.DataFrame) -> pd.DataFrame:
    if rules_df.empty or "Path" not in rules_df.columns:
        return rules_df
    df = normalize_final_rule_certificates(rules_df).copy().reset_index(drop=True)
    drop_indexes = set()
    records = df.to_dict("records")
    for i, broad in enumerate(records):
        if is_dangerous_user_wildcard_rule(broad.get("Path")):
            continue
        broad_conditions = count_rule_conditions(broad)
        for j, narrow in enumerate(records):
            if i == j or j in drop_indexes:
                continue
            if count_rule_conditions(narrow) < broad_conditions:
                continue
            if rule_is_covered(broad, narrow):
                drop_indexes.add(j)
    if drop_indexes:
        df = df.drop(index=list(drop_indexes), errors="ignore")
    return df.reset_index(drop=True)


def build_final_rules(candidate_pairs: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    if candidate_pairs.empty:
        return pd.DataFrame(columns=["Path", "Certificate", "Process Path", "Created By"])
    rules_df = _base_build_final_rules(candidate_pairs, settings)
    if rules_df.empty:
        return rules_df
    for col in ["Path", "Certificate", "Process Path", "Created By"]:
        if col not in rules_df.columns:
            rules_df[col] = None

    rules_df = normalize_final_rule_certificates(rules_df)
    rules_df = filter_dangerous_rules(rules_df, settings)
    rules_df = add_certificate_anchor_rules(rules_df, settings)
    rules_df = compress_language_folder_families(rules_df, settings)
    rules_df = compress_extension_families_global(rules_df, settings)
    rules_df = normalize_final_rule_certificates(rules_df)
    rules_df = suppress_covered_rules(rules_df)
    rules_df = filter_dangerous_rules(rules_df, settings)
    rules_df = enforce_high_risk_process_rules(rules_df, settings)

    final_columns = ["Path", "Certificate", "Process Path", "Created By"]
    for col in final_columns:
        if col not in rules_df.columns:
            rules_df[col] = None
    rules_df = rules_df[final_columns].copy()
    rules_df = normalize_final_rule_certificates(rules_df)
    rules_df = rules_df.drop_duplicates().dropna(how="all").reset_index(drop=True)
    return rules_df


def add_risk_review_columns(rules_df: pd.DataFrame) -> pd.DataFrame:
    if rules_df.empty:
        return rules_df
    df = rules_df.copy()
    df["Condition Count"] = df.apply(lambda r: count_rule_conditions(r.to_dict()), axis=1)
    df["Risk Score"] = df.apply(lambda r: rule_risk_score(r.to_dict()), axis=1)
    df["Risk"] = df["Risk Score"].map(risk_label)
    df["Wildcard Count"] = df["Path"].fillna("").astype(str).map(lambda x: x.count("*")) if "Path" in df.columns else 0
    return df.sort_values(["Risk Score", "Condition Count", "Wildcard Count"], ascending=[True, False, True]).reset_index(drop=True)


def build_outputs(df: pd.DataFrame, settings: RuleSettings) -> Dict[str, pd.DataFrame]:
    parsed = apply_parsing(df)
    combined_review = parsed[[c for c in ["path", "process_path", "certificate_primary", "created_by", "sha256_hash", "md5_hash", "hostname", "timestamp_utc", "count", "Notes"] if c in parsed.columns]].copy()
    combined_review.columns = [
        "Path" if c == "path" else
        "Process Path" if c == "process_path" else
        "Certificate" if c == "certificate_primary" else
        "Created By" if c == "created_by" else
        "SHA256" if c == "sha256_hash" else
        "MD5" if c == "md5_hash" else
        "Host Name" if c == "hostname" else
        "Timestamp" if c == "timestamp_utc" else
        "Count" if c == "count" else c
        for c in combined_review.columns
    ]
    detailed = build_candidate_pairs(parsed, settings)
    rule_pairs_export = build_pair_export(detailed)
    final_rules = build_final_rules(detailed, settings)
    risk_review = add_risk_review_columns(final_rules)
    return {
        "parsed": parsed,
        "combined_review": combined_review,
        "candidate_rule_pairs": detailed,
        "rule_pairs_export": rule_pairs_export,
        "final_rules": final_rules,
        "risk_review": risk_review,
    }

# ============================================================
# v4 Optimizer Overrides - macOS/Python consolidation cleanup
# ============================================================
# Findings from selected_optimized_rules.csv showed macOS Python records were
# producing rules where "added by" metadata was embedded inside Process Path,
# AppTranslocation paths were not normalized to the real app bundle, and
# /Library rows occasionally contained inline process/cert metadata. These
# overrides keep Windows behavior intact while hardening macOS output.

_v3_apply_parsing = apply_parsing
_v3_build_final_rules = build_final_rules
_v3_add_risk_review_columns = add_risk_review_columns

MAC_APP_TRANSLOCATION_RE = re.compile(
    r"(?i)^/private/var/folders/[^/]+/[^/]+/t/apptranslocation/\*/d/(?P<bundle>.+?\.app/contents/.+)$"
)
MAC_VSCODE_EXTENSION_VERSION_RE = re.compile(
    r"(?i)(/users/\*/\.vscode/extensions/[^/]+?)-\d+(?:\.\d+)*(?:-[^/]*)?/"
)
INLINE_ADDED_BY_RE = re.compile(r"(?i)\s+added\s+by:\s*(?P<creator>[^\r\n]+?)\s*$")
INLINE_MERGED_BY_RE = re.compile(r"(?i)\s+merged\s+by:\s*(?P<creator>[^\r\n]+?)\s+\d{4}-\d{2}-\d{2}.*$")
INLINE_FIELD_RE = re.compile(r"(?i)\s+(?:process|processpath|process path|installedby|installed by|createdby|created by|cert|certificate)=.*$")


def normalize_path(value: Optional[str]) -> Optional[str]:
    """Normalize Windows and POSIX paths without converting macOS '/' into '\\'."""
    value = normalize_spaces(value)
    if not value:
        return None
    raw = str(value).strip().strip('"').strip("'")
    # Strip accidental inline metadata before path normalization.
    raw = INLINE_FIELD_RE.sub("", raw).strip()
    raw = INLINE_ADDED_BY_RE.sub("", raw).strip()
    raw = INLINE_MERGED_BY_RE.sub("", raw).strip()
    if re.match(r"(?i)^[a-z]:[\\/]", raw):
        raw = raw.replace("/", "\\")
        raw = re.sub(r"\\+", r"\\", raw)
        return raw.lower()
    if raw.startswith("/"):
        raw = re.sub(r"/+", "/", raw)
        return raw.rstrip("/").lower() if raw != "/" else raw
    return raw.lower()

try:
    _normalize_path_cached.cache_clear()
    _convert_to_normalized_path_cached.cache_clear()
except Exception:
    pass


def split_added_by_from_value(value: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    text = normalize_spaces(value)
    if not text:
        return None, None
    m = INLINE_ADDED_BY_RE.search(text)
    if not m:
        m = INLINE_MERGED_BY_RE.search(text)
    if not m:
        return text, None
    creator = normalize_spaces(m.group("creator"))
    cleaned = normalize_spaces(text[:m.start()])
    return cleaned, creator


def clean_inline_rule_metadata(value: Optional[str]) -> Optional[str]:
    text = normalize_spaces(value)
    if not text:
        return None
    cleaned, _creator = split_added_by_from_value(text)
    cleaned = INLINE_FIELD_RE.sub("", cleaned or "").strip()
    return normalize_spaces(cleaned)


def normalize_macos_process_path(value: Optional[str]) -> Optional[str]:
    p = normalize_path(value)
    if not p:
        return None
    m = MAC_APP_TRANSLOCATION_RE.match(p)
    if m:
        # AppTranslocation paths are randomized. Anchor back to the visible app bundle.
        p = "/applications/" + m.group("bundle").lower()
    p = MAC_VSCODE_EXTENSION_VERSION_RE.sub(r"\1-*/", p)
    p = re.sub(r"(?i)(/opt/homebrew/cellar/[^/]+)/[^/]+/", r"\1/*/", p)
    p = re.sub(r"(?i)(/usr/local/homebrew/[^ ]*?/portable-ruby)/[^/]+/", r"\1/*/", p)
    p = re.sub(r"(?i)(/library/frameworks/python\.framework/versions)/[^/]+/", r"\1/*/", p)
    return p


def normalize_macos_target_path(value: Optional[str]) -> Optional[str]:
    p = normalize_path(value)
    if not p:
        return None
    if " process=" in p or " installedby=" in p or " cert=" in p:
        p = clean_inline_rule_metadata(p)
        p = normalize_path(p)
    # Keep Python framework/app major-minor anchors stable but do not collapse
    # Python 3.11, 3.12, 3.13 into one broad /applications/* rule.
    p = re.sub(r"(?i)^/library/frameworks/python\.framework/versions/[^/]+/", "/library/frameworks/python.framework/versions/*/", p)
    # Normalize app bundle contents to the bundle root where appropriate.
    app_match = re.match(r"(?i)^(.+?\.app)(?:/contents/.*)?$", p)
    if app_match:
        return app_match.group(1).lower() + "/*"
    return p


def is_macos_high_risk_process_path(value: Optional[str]) -> bool:
    p = normalize_path(value) or ""
    base = p.rstrip("/").split("/")[-1].lower()
    if base in {
        "bash", "zsh", "sh", "osascript", "python", "python3", "ruby", "perl", "node", "npm",
        "curl", "wget", "installer", "pkgutil", "launchctl", "sudo", "su", "chmod", "chown",
        "xattr", "codesign", "spctl", "tccutil", "plutil", "defaults", "open"
    }:
        return True
    if p.startswith(("/private/var/", "/var/folders/", "/tmp/", "/users/")):
        return True
    return False


def is_high_risk_process_path(value: Optional[str]) -> bool:
    p = normalize_path(value) or ""
    if p.startswith("/"):
        return is_macos_high_risk_process_path(p)
    base = basename_from_path(p)
    if base in HIGH_RISK_PROCESS_BASENAMES:
        return True
    if any(re.search(pattern, p, re.IGNORECASE) for pattern in HIGH_RISK_PROCESS_DIR_PATTERNS):
        if base.endswith((".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js")):
            return True
    return False


def apply_parsing(df: pd.DataFrame) -> pd.DataFrame:
    parsed = _v3_apply_parsing(df)
    if parsed.empty:
        return parsed
    if "created_by" not in parsed.columns:
        parsed["created_by"] = None
    for idx, row in parsed.iterrows():
        # Pull Added By / Merged By metadata out of Process Path or Path.
        for col in ["process_path", "path"]:
            if col not in parsed.columns:
                continue
            cleaned, creator = split_added_by_from_value(row.get(col))
            if creator and not normalize_spaces(parsed.at[idx, "created_by"]):
                parsed.at[idx, "created_by"] = creator
            if cleaned:
                parsed.at[idx, col] = cleaned
        if "path" in parsed.columns:
            parsed.at[idx, "path"] = normalize_macos_target_path(parsed.at[idx, "path"])
            parsed.at[idx, "wildcard_path"] = shorten_leaf(parsed.at[idx, "path"])
        if "process_path" in parsed.columns:
            parsed.at[idx, "process_path"] = normalize_macos_process_path(parsed.at[idx, "process_path"])
    if "row_fingerprint" in parsed.columns:
        parsed["row_fingerprint"] = parsed.apply(
            lambda row: " | ".join([
                normalize_spaces(row.get("path")) or "",
                normalize_spaces(row.get("process_path")) or "",
                normalize_spaces(row.get("certificate_primary")) or "",
                normalize_spaces(row.get("created_by")) or "",
                normalize_spaces(row.get("sha256_hash")) or normalize_spaces(row.get("md5_hash")) or "",
            ]), axis=1
        )
    return parsed


def sanitize_final_rule_values(rules_df: pd.DataFrame) -> pd.DataFrame:
    if rules_df.empty:
        return rules_df
    df = rules_df.copy()
    for existing_col in ["Path", "Process Path", "Certificate", "Created By"]:
        if existing_col in df.columns:
            df[existing_col] = df[existing_col].astype("object")
    for col in ["Path", "Process Path", "Certificate", "Created By"]:
        if col not in df.columns:
            df[col] = None
    for idx, row in df.iterrows():
        path_clean, path_creator = split_added_by_from_value(row.get("Path"))
        proc_clean, proc_creator = split_added_by_from_value(row.get("Process Path"))
        creator = normalize_spaces(row.get("Created By")) or proc_creator or path_creator
        df.at[idx, "Path"] = normalize_macos_target_path(path_clean)
        df.at[idx, "Process Path"] = normalize_macos_process_path(proc_clean)
        df.at[idx, "Created By"] = creator
    df = normalize_final_rule_certificates(df)
    # Remove known broken rows where metadata became part of the path.
    df = df[~df["Path"].fillna("").astype(str).str.contains(r"(?i)\sprocess=|\sinstalledby=|\scert=")].copy()
    return df


def compress_macos_python_consolidation(rules_df: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    """Collapse duplicate macOS Python rules after process-path and creator cleanup."""
    if rules_df.empty:
        return rules_df
    df = sanitize_final_rule_values(rules_df)
    # Normalize common Python app/library anchors.
    df["Path"] = df["Path"].map(lambda p: re.sub(r"(?i)^/applications/python\s+(\d+\.\d+)/.*$", r"/applications/python \1/*", str(p)) if normalize_spaces(p) else p)
    df["Path"] = df["Path"].map(lambda p: re.sub(r"(?i)^/library/python/[^/]+/", "/library/python/*/", str(p)) if normalize_spaces(p) else p)
    # Deduplicate after process translocation and Added By normalization.
    final_columns = ["Path", "Certificate", "Process Path", "Created By"]
    df = df[final_columns]
    df = df.drop_duplicates().dropna(how="all").reset_index(drop=True)
    return df


def filter_dangerous_rules(rules_df: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    if rules_df.empty:
        return rules_df
    df = sanitize_final_rule_values(rules_df)
    rows = []
    for _, row in df.iterrows():
        rd = row.to_dict()
        path = normalize_spaces(rd.get("Path"))
        proc = normalize_spaces(rd.get("Process Path"))
        cond_count = count_rule_conditions(rd)
        if is_dangerous_user_wildcard_rule(path):
            continue
        if is_user_writable_path(path) and cond_count < 3:
            continue
        # macOS user/temp process paths must be constrained with Created By or Certificate.
        if proc and proc.startswith(("/users/", "/private/var/", "/var/folders/", "/tmp/")) and cond_count < 3:
            continue
        rows.append(rd)
    return pd.DataFrame(rows, columns=df.columns if not df.empty else None)


def enforce_high_risk_process_rules(rules_df: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    if rules_df.empty or not getattr(settings, "enforce_high_risk_process_three_conditions", True):
        return rules_df
    df = sanitize_final_rule_values(rules_df)
    min_conditions = int(getattr(settings, "high_risk_process_min_conditions", 3) or 3)
    rows = []
    for _, row in df.iterrows():
        rd = row.to_dict()
        process_path = normalize_spaces(rd.get("Process Path"))
        if process_path and is_high_risk_process_path(process_path):
            if count_rule_conditions(rd) < min_conditions:
                continue
        rows.append(rd)
    return pd.DataFrame(rows, columns=df.columns if not df.empty else None)


def build_final_rules(candidate_pairs: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    rules_df = _v3_build_final_rules(candidate_pairs, settings)
    if rules_df.empty:
        return rules_df
    rules_df = compress_macos_python_consolidation(rules_df, settings)
    rules_df = filter_dangerous_rules(rules_df, settings)
    rules_df = enforce_high_risk_process_rules(rules_df, settings)
    final_columns = ["Path", "Certificate", "Process Path", "Created By"]
    for col in final_columns:
        if col not in rules_df.columns:
            rules_df[col] = None
    rules_df = rules_df[final_columns].copy()
    rules_df = normalize_final_rule_certificates(rules_df)
    rules_df = rules_df.drop_duplicates().dropna(how="all").reset_index(drop=True)
    return rules_df


def add_risk_review_columns(rules_df: pd.DataFrame) -> pd.DataFrame:
    df = sanitize_final_rule_values(rules_df)
    if df.empty:
        return df
    df["Condition Count"] = df.apply(lambda r: count_rule_conditions(r.to_dict()), axis=1)
    df["Risk Score"] = df.apply(lambda r: rule_risk_score(r.to_dict()), axis=1)
    df["Risk"] = df["Risk Score"].map(risk_label)
    df["Wildcard Count"] = df["Path"].fillna("").astype(str).map(lambda x: x.count("*")) if "Path" in df.columns else 0
    df["Review Notes"] = df.apply(
        lambda r: "High-risk process path requires 3 conditions" if is_high_risk_process_path(r.get("Process Path")) else "",
        axis=1,
    )
    return df.sort_values(["Risk Score", "Condition Count", "Wildcard Count"], ascending=[True, False, True]).reset_index(drop=True)


def build_outputs(df: pd.DataFrame, settings: RuleSettings) -> Dict[str, pd.DataFrame]:
    parsed = apply_parsing(df)
    combined_review = parsed[[c for c in ["path", "process_path", "certificate_primary", "created_by", "sha256_hash", "md5_hash", "hostname", "timestamp_utc", "count", "Notes"] if c in parsed.columns]].copy()
    combined_review.columns = [
        "Path" if c == "path" else
        "Process Path" if c == "process_path" else
        "Certificate" if c == "certificate_primary" else
        "Created By" if c == "created_by" else
        "SHA256" if c == "sha256_hash" else
        "MD5" if c == "md5_hash" else
        "Host Name" if c == "hostname" else
        "Timestamp" if c == "timestamp_utc" else
        "Count" if c == "count" else c
        for c in combined_review.columns
    ]
    detailed = build_candidate_pairs(parsed, settings)
    rule_pairs_export = build_pair_export(detailed)
    final_rules = build_final_rules(detailed, settings)
    risk_review = add_risk_review_columns(final_rules)
    return {
        "parsed": parsed,
        "combined_review": combined_review,
        "candidate_rule_pairs": detailed,
        "rule_pairs_export": rule_pairs_export,
        "final_rules": final_rules,
        "risk_review": risk_review,
    }

# ============================================================
# v5 Optimizer Overrides - Python macOS output hardening
# ============================================================
# Findings from parsed rules (2).csv and selected_optimized_rules (2).csv:
#   - Process Path sometimes became a literal '*' and was counted as a valid condition.
#   - Rules like /users/*/library/* and /applications/*/* were too broad for Python cleanup.
#   - User Library Python/site-packages records were over-compressed above the package level.
#   - Apple private framework helper processes were creating weak two-condition rules.
# These overrides keep useful Python app bundle compression while filtering broad/noisy macOS rules.

_v4_build_final_rules = build_final_rules
_v4_add_risk_review_columns = add_risk_review_columns
_v4_sanitize_final_rule_values = sanitize_final_rule_values
_v4_rule_risk_score = rule_risk_score

MACOS_INVALID_PROCESS_VALUES = {"*", "/*", "/applications/*", "/applications/*/*"}
MACOS_BROAD_PATH_PATTERNS = (
    re.compile(r"(?i)^/applications/\*/\*$"),
    re.compile(r"(?i)^/applications/\*/\*/?$"),
    re.compile(r"(?i)^/users/\*/library/\*$"),
    re.compile(r"(?i)^/users/\*/library/python/\*$"),
    re.compile(r"(?i)^/users/\*/\.pyenv/\*$"),
)
MACOS_PYTHON_SITE_PACKAGES_RE = re.compile(
    r"(?i)^/users/([^/]+)/library/python/([^/]+)/lib/python/site-packages/([^/]+)(?:/.*)?$"
)
MACOS_PYTHON_SITE_PACKAGES_WILDCARD_RE = re.compile(
    r"(?i)^/users/\*/library/python/\*/lib/python/site-packages/([^/]+)/\*$"
)
APPLE_PRIVATE_FRAMEWORK_PROCESS_RE = re.compile(r"(?i)^/system/(?:volumes/preboot/cryptexes/os/system/)?library/privateframeworks/")


def is_invalid_process_condition(value: Optional[str]) -> bool:
    p = normalize_path(value) or normalize_spaces(value) or ""
    return p.strip().lower() in MACOS_INVALID_PROCESS_VALUES


def is_overbroad_macos_path(path: Optional[str]) -> bool:
    p = normalize_path(path) or ""
    if not p.startswith("/"):
        return False
    return any(rx.fullmatch(p) for rx in MACOS_BROAD_PATH_PATTERNS)


def is_specific_python_site_package_rule(path: Optional[str]) -> bool:
    p = normalize_path(path) or ""
    return bool(MACOS_PYTHON_SITE_PACKAGES_WILDCARD_RE.fullmatch(p))


def normalize_python_site_packages_path(path: Optional[str]) -> Optional[str]:
    p = normalize_path(path)
    if not p:
        return None
    m = MACOS_PYTHON_SITE_PACKAGES_RE.match(p)
    if not m:
        return p
    package = m.group(3).lower()
    # Keep native binary package leaves specific enough, but collapse user and Python minor version.
    return f"/users/*/library/python/*/lib/python/site-packages/{package}/*"


def sanitize_final_rule_values(rules_df: pd.DataFrame) -> pd.DataFrame:
    df = _v4_sanitize_final_rule_values(rules_df)
    if df.empty:
        return df
    for col in ["Path", "Process Path", "Certificate", "Created By"]:
        if col not in df.columns:
            df[col] = None
    for idx, row in df.iterrows():
        path = normalize_macos_target_path(row.get("Path"))
        proc = normalize_macos_process_path(row.get("Process Path"))
        if is_invalid_process_condition(proc):
            proc = None
        path = normalize_python_site_packages_path(path)
        df.at[idx, "Path"] = path
        df.at[idx, "Process Path"] = proc
    df = normalize_final_rule_certificates(df)
    return df


def count_rule_conditions(rule: Dict[str, Optional[str]]) -> int:
    count = 0
    for key in ["Path", "Process Path", "Certificate", "Created By"]:
        value = normalize_spaces(rule.get(key))
        if not value:
            continue
        if key == "Process Path" and is_invalid_process_condition(value):
            continue
        count += 1
    return count


def is_macos_user_python_library_path(path: Optional[str]) -> bool:
    p = normalize_path(path) or ""
    return p.startswith("/users/") and "/library/python/" in p


def filter_dangerous_rules(rules_df: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    if rules_df.empty:
        return rules_df
    df = sanitize_final_rule_values(rules_df)
    rows = []
    for _, row in df.iterrows():
        rd = row.to_dict()
        path = normalize_spaces(rd.get("Path"))
        proc = normalize_spaces(rd.get("Process Path"))
        cert = normalize_spaces(rd.get("Certificate"))
        created_by = normalize_spaces(rd.get("Created By"))
        cond_count = count_rule_conditions(rd)

        if not path:
            continue
        if is_invalid_process_condition(proc):
            rd["Process Path"] = None
            proc = None
            cond_count = count_rule_conditions(rd)
        if is_dangerous_user_wildcard_rule(path):
            continue
        if is_overbroad_macos_path(path):
            continue
        # Do not keep weak user-library rules unless they are package-scoped and have a real supporting condition.
        if is_macos_user_python_library_path(path):
            if not is_specific_python_site_package_rule(path):
                if cond_count < 3:
                    continue
            if not (proc or cert or created_by):
                continue
        # Apple private framework helpers are OS telemetry/helper processes; require an extra anchor.
        if proc and APPLE_PRIVATE_FRAMEWORK_PROCESS_RE.match(proc) and cond_count < 3:
            continue
        if is_user_writable_path(path) and cond_count < 3:
            continue
        if proc and proc.startswith(("/users/", "/private/var/", "/var/folders/", "/tmp/")) and cond_count < 3:
            continue
        rows.append(rd)
    return pd.DataFrame(rows, columns=df.columns if not df.empty else None)


def compress_macos_python_consolidation(rules_df: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    if rules_df.empty:
        return rules_df
    df = sanitize_final_rule_values(rules_df)
    # Keep Python application versions, but collapse bundle content safely.
    df["Path"] = df["Path"].map(lambda p: re.sub(r"(?i)^/applications/python\s+(\d+\.\d+)/(.+?\.app)(?:/.*)?$", r"/applications/python \1/\2/*", str(p)) if normalize_spaces(p) else p)
    df["Path"] = df["Path"].map(lambda p: re.sub(r"(?i)^/applications/python\s+(\d+\.\d+)/[^/]+$", r"/applications/python \1/*", str(p)) if normalize_spaces(p) else p)
    df["Path"] = df["Path"].map(normalize_python_site_packages_path)
    final_columns = ["Path", "Certificate", "Process Path", "Created By"]
    for col in final_columns:
        if col not in df.columns:
            df[col] = None
    df = df[final_columns]
    df = df.drop_duplicates().dropna(how="all").reset_index(drop=True)
    return df


def enforce_high_risk_process_rules(rules_df: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    if rules_df.empty or not getattr(settings, "enforce_high_risk_process_three_conditions", True):
        return rules_df
    df = sanitize_final_rule_values(rules_df)
    min_conditions = int(getattr(settings, "high_risk_process_min_conditions", 3) or 3)
    rows = []
    for _, row in df.iterrows():
        rd = row.to_dict()
        process_path = normalize_spaces(rd.get("Process Path"))
        if process_path and is_high_risk_process_path(process_path):
            if count_rule_conditions(rd) < min_conditions:
                continue
        rows.append(rd)
    return pd.DataFrame(rows, columns=df.columns if not df.empty else None)


def rule_risk_score(row: Dict[str, object]) -> int:
    score = _v4_rule_risk_score(row)
    path = normalize_spaces(row.get("Path"))
    proc = normalize_spaces(row.get("Process Path"))
    if is_invalid_process_condition(proc):
        score += 10
    if is_overbroad_macos_path(path):
        score += 15
    if proc and APPLE_PRIVATE_FRAMEWORK_PROCESS_RE.match(proc):
        score += 5
    if is_macos_user_python_library_path(path) and not is_specific_python_site_package_rule(path):
        score += 6
    return score


def build_final_rules(candidate_pairs: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    rules_df = _v4_build_final_rules(candidate_pairs, settings)
    if rules_df.empty:
        return rules_df
    rules_df = compress_macos_python_consolidation(rules_df, settings)
    rules_df = filter_dangerous_rules(rules_df, settings)
    rules_df = enforce_high_risk_process_rules(rules_df, settings)
    final_columns = ["Path", "Certificate", "Process Path", "Created By"]
    for col in final_columns:
        if col not in rules_df.columns:
            rules_df[col] = None
    rules_df = rules_df[final_columns].copy()
    rules_df = normalize_final_rule_certificates(rules_df)
    rules_df = rules_df.drop_duplicates().dropna(how="all").reset_index(drop=True)
    return rules_df


def add_risk_review_columns(rules_df: pd.DataFrame) -> pd.DataFrame:
    df = sanitize_final_rule_values(rules_df)
    if df.empty:
        return df
    df["Condition Count"] = df.apply(lambda r: count_rule_conditions(r.to_dict()), axis=1)
    df["Risk Score"] = df.apply(lambda r: rule_risk_score(r.to_dict()), axis=1)
    df["Risk"] = df["Risk Score"].map(risk_label)
    df["Wildcard Count"] = df["Path"].fillna("").astype(str).map(lambda x: x.count("*")) if "Path" in df.columns else 0
    df["Review Notes"] = df.apply(
        lambda r: (
            "Invalid wildcard process path" if is_invalid_process_condition(r.get("Process Path")) else
            "Overbroad macOS wildcard path" if is_overbroad_macos_path(r.get("Path")) else
            "Apple private framework helper requires extra anchor" if normalize_spaces(r.get("Process Path")) and APPLE_PRIVATE_FRAMEWORK_PROCESS_RE.match(normalize_spaces(r.get("Process Path"))) else
            "High-risk process path requires 3 conditions" if is_high_risk_process_path(r.get("Process Path")) else
            ""
        ),
        axis=1,
    )
    return df.sort_values(["Risk Score", "Condition Count", "Wildcard Count"], ascending=[True, False, True]).reset_index(drop=True)


def build_outputs(df: pd.DataFrame, settings: RuleSettings) -> Dict[str, pd.DataFrame]:
    parsed = apply_parsing(df)
    combined_review = parsed[[c for c in ["path", "process_path", "certificate_primary", "created_by", "sha256_hash", "md5_hash", "hostname", "timestamp_utc", "count", "Notes"] if c in parsed.columns]].copy()
    combined_review.columns = [
        "Path" if c == "path" else
        "Process Path" if c == "process_path" else
        "Certificate" if c == "certificate_primary" else
        "Created By" if c == "created_by" else
        "SHA256" if c == "sha256_hash" else
        "MD5" if c == "md5_hash" else
        "Host Name" if c == "hostname" else
        "Timestamp" if c == "timestamp_utc" else
        "Count" if c == "count" else c
        for c in combined_review.columns
    ]
    detailed = build_candidate_pairs(parsed, settings)
    rule_pairs_export = build_pair_export(detailed)
    final_rules = build_final_rules(detailed, settings)
    risk_review = add_risk_review_columns(final_rules)
    return {
        "parsed": parsed,
        "combined_review": combined_review,
        "candidate_rule_pairs": detailed,
        "rule_pairs_export": rule_pairs_export,
        "final_rules": final_rules,
        "risk_review": risk_review,
    }

# v5.1 - macOS user-writable guardrail
_v5_filter_dangerous_rules = filter_dangerous_rules
_v5_rule_risk_score = rule_risk_score
_v5_build_final_rules = build_final_rules
_v5_add_risk_review_columns = add_risk_review_columns


def is_macos_user_writable_path(path: Optional[str]) -> bool:
    p = normalize_path(path) or ""
    return p.startswith(("/users/", "/private/var/", "/var/folders/", "/tmp/", "/var/tmp/"))


def filter_dangerous_rules(rules_df: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    if rules_df.empty:
        return rules_df
    df = sanitize_final_rule_values(rules_df)
    rows = []
    for _, row in df.iterrows():
        rd = row.to_dict()
        path = normalize_spaces(rd.get("Path"))
        proc = normalize_spaces(rd.get("Process Path"))
        cond_count = count_rule_conditions(rd)
        if cond_count < 2:
            continue
        if is_invalid_process_condition(proc):
            rd["Process Path"] = None
            proc = None
            cond_count = count_rule_conditions(rd)
        if cond_count < 2:
            continue
        if is_dangerous_user_wildcard_rule(path) or is_overbroad_macos_path(path):
            continue
        # macOS user-writable Python/package paths are high churn and user-controlled.
        # Require at least 3 anchors before generating final uploadable rules.
        if is_macos_user_writable_path(path) and cond_count < 3:
            continue
        if is_user_writable_path(path) and cond_count < 3:
            continue
        if proc and APPLE_PRIVATE_FRAMEWORK_PROCESS_RE.match(proc) and cond_count < 3:
            continue
        if proc and proc.startswith(("/users/", "/private/var/", "/var/folders/", "/tmp/", "/var/tmp/")) and cond_count < 3:
            continue
        rows.append(rd)
    return pd.DataFrame(rows, columns=df.columns if not df.empty else None)


def rule_risk_score(row: Dict[str, object]) -> int:
    score = _v5_rule_risk_score(row)
    if is_macos_user_writable_path(row.get("Path")) and count_rule_conditions(row) < 3:
        score += 10
    return score


def build_final_rules(candidate_pairs: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    rules_df = _v5_build_final_rules(candidate_pairs, settings)
    if rules_df.empty:
        return rules_df
    rules_df = filter_dangerous_rules(rules_df, settings)
    rules_df = enforce_high_risk_process_rules(rules_df, settings)
    final_columns = ["Path", "Certificate", "Process Path", "Created By"]
    for col in final_columns:
        if col not in rules_df.columns:
            rules_df[col] = None
    rules_df = rules_df[final_columns].copy()
    rules_df = normalize_final_rule_certificates(rules_df)
    return rules_df.drop_duplicates().dropna(how="all").reset_index(drop=True)

# ============================================================
# v6 Optimizer Overrides - macOS Python developer-app tuning
# ============================================================
# Addresses observed Python/Xcode consolidation issue where macOS process
# paths were supplied in the Certificate column and later filtered out because
# macOS user-writable paths required 3 conditions. This layer:
#   - remaps path-like Certificate values into Process Path when appropriate
#   - prevents path-like values from becoming certificate conditions
#   - allows specific Python package/native-extension rules with Path + Process
#     when the path anchor is project/package-specific and not overbroad
#   - keeps broad /Users, /Library, /Applications wildcard guardrails intact

_v6_base_apply_parsing = apply_parsing
_v6_base_normalize_for_pair = normalize_for_pair
_v6_base_filter_dangerous_rules = filter_dangerous_rules
_v6_base_rule_risk_score = rule_risk_score
_v6_base_build_final_rules = build_final_rules


def value_looks_like_filesystem_path(value: Optional[str]) -> bool:
    v = normalize_spaces(value) or ""
    if not v:
        return False
    return bool(re.match(r"(?i)^[a-z]:[\\/]", v) or v.startswith("/"))


def value_looks_like_certificate(value: Optional[str]) -> bool:
    v = normalize_spaces(value) or ""
    if not v:
        return False
    if value_looks_like_filesystem_path(v):
        return False
    return bool(re.search(r"(?i)(^|[,;|]\s*)(o|cn)\s*=", v)) or not any(sep in v for sep in ["/", "\\"])


def is_python_interpreter_path(value: Optional[str]) -> bool:
    p = normalize_path(value) or ""
    if not p:
        return False
    base = p.replace("\\", "/").rstrip("/").split("/")[-1]
    return bool(re.match(r"(?i)^python(?:\d+(?:\.\d+)*)?$", base)) or "/python.app/contents/macos/python" in p


def mac_path_depth(path: Optional[str]) -> int:
    p = normalize_path(path) or ""
    if not p.startswith("/"):
        return 0
    return len([x for x in p.split("/") if x])


def is_macos_python_package_artifact(path: Optional[str]) -> bool:
    p = normalize_path(path) or ""
    if not p.startswith("/users/"):
        return False
    if is_overbroad_macos_path(p) or is_dangerous_user_wildcard_rule(p):
        return False
    markers = (
        "/.venv/", "/venv/", "/site-packages/", "/lib/python", "/miniconda", "/anaconda",
        "/.pyenv/versions/", "/.local/share/uv/python/", "/uv/python/",
    )
    if not any(marker in p for marker in markers):
        return False
    # Native Python dependency artifacts are commonly unsigned on macOS; allow
    # project/package-specific anchors, but not generic user-folder wildcards.
    leaf = p.rsplit("/", 1)[-1]
    if not (leaf.endswith((".so", ".dylib", ".pyd", ".a")) or leaf in {"*", "*.so", "*.dylib", "*.pyd"}):
        return False
    return mac_path_depth(p) >= 6


def is_safe_macos_python_two_condition_rule(rule: Dict[str, object]) -> bool:
    path = normalize_spaces(rule.get("Path"))
    proc = normalize_spaces(rule.get("Process Path"))
    cert = normalize_spaces(rule.get("Certificate"))
    created = normalize_spaces(rule.get("Created By"))
    if cert or created:
        return False
    if not path or not proc:
        return False
    if count_rule_conditions(rule) != 2:
        return False
    if not is_python_interpreter_path(proc):
        return False
    if not is_macos_python_package_artifact(path):
        return False
    if (normalize_path(path) or "").count("*") > 2:
        return False
    return True


def apply_parsing(df: pd.DataFrame) -> pd.DataFrame:
    parsed = _v6_base_apply_parsing(df)
    if parsed.empty:
        return parsed

    # Some macOS exports/previous optimized app records put the Python launcher
    # path in Certificate while Process Path is empty. Remap those rows so the
    # rule generator builds Path + Process Path instead of Path + fake cert.
    for idx, row in parsed.iterrows():
        cert = normalize_spaces(row.get("certificate_primary"))
        proc = normalize_spaces(row.get("process_path"))
        if cert and not proc and value_looks_like_filesystem_path(cert):
            parsed.at[idx, "process_path"] = normalize_path(cert)
            for col in ["certificate_primary", "certificate_raw", "certificate_all"]:
                if col in parsed.columns:
                    parsed.at[idx, col] = None

    if "row_fingerprint" in parsed.columns:
        parsed["row_fingerprint"] = parsed.apply(
            lambda row: " | ".join([
                normalize_spaces(row.get("path")) or "",
                normalize_spaces(row.get("process_path")) or "",
                normalize_spaces(row.get("certificate_primary")) or "",
                normalize_spaces(row.get("created_by")) or "",
                normalize_spaces(row.get("sha256_hash")) or normalize_spaces(row.get("md5_hash")) or "",
            ]), axis=1
        )
    return parsed


def normalize_for_pair(value: Optional[str], kind: str, settings: RuleSettings) -> Dict[str, str]:
    # Never allow a filesystem path to become a Certificate condition.
    if kind == "Certificate" and value_looks_like_filesystem_path(value):
        return {"key": "", "wildcard": ""}
    return _v6_base_normalize_for_pair(value, kind, settings)


def filter_dangerous_rules(rules_df: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    if rules_df.empty:
        return rules_df
    df = sanitize_final_rule_values(rules_df) if "sanitize_final_rule_values" in globals() else rules_df.copy()
    rows = []
    for _, row in df.iterrows():
        rd = row.to_dict()
        # Allow specific Python native dependency rules even with only Path + Process Path.
        # This prevents Python/Xcode consolidations from collapsing to only a few Apple cert rules.
        if is_safe_macos_python_two_condition_rule(rd):
            rows.append(rd)
            continue
        # Otherwise keep the existing v5 guardrails.
        tmp = pd.DataFrame([rd], columns=df.columns)
        filtered = _v6_base_filter_dangerous_rules(tmp, settings)
        if not filtered.empty:
            rows.extend(filtered.to_dict("records"))
    return pd.DataFrame(rows, columns=df.columns if not df.empty else None)


def rule_risk_score(row: Dict[str, object]) -> int:
    if is_safe_macos_python_two_condition_rule(row):
        # Still reviewable, but not treated like a generic /Users wildcard.
        return 5
    return _v6_base_rule_risk_score(row)


def build_final_rules(candidate_pairs: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    rules_df = _v6_base_build_final_rules(candidate_pairs, settings)
    if rules_df.empty:
        return rules_df
    rules_df = filter_dangerous_rules(rules_df, settings)
    rules_df = enforce_high_risk_process_rules(rules_df, settings)
    final_columns = ["Path", "Certificate", "Process Path", "Created By"]
    for col in final_columns:
        if col not in rules_df.columns:
            rules_df[col] = None
    rules_df = rules_df[final_columns].copy()
    rules_df = normalize_final_rule_certificates(rules_df)
    return rules_df.drop_duplicates().dropna(how="all").reset_index(drop=True)


def build_outputs(df: pd.DataFrame, settings: RuleSettings) -> Dict[str, pd.DataFrame]:
    parsed = apply_parsing(df)
    combined_review = parsed[[c for c in ["path", "process_path", "certificate_primary", "created_by", "sha256_hash", "md5_hash", "hostname", "timestamp_utc", "count", "Notes"] if c in parsed.columns]].copy()
    combined_review.columns = [
        "Path" if c == "path" else
        "Process Path" if c == "process_path" else
        "Certificate" if c == "certificate_primary" else
        "Created By" if c == "created_by" else
        "SHA256" if c == "sha256_hash" else
        "MD5" if c == "md5_hash" else
        "Host Name" if c == "hostname" else
        "Timestamp" if c == "timestamp_utc" else
        "Count" if c == "count" else c
        for c in combined_review.columns
    ]
    detailed = build_candidate_pairs(parsed, settings)
    rule_pairs_export = build_pair_export(detailed)
    final_rules = build_final_rules(detailed, settings)
    risk_review = add_risk_review_columns(final_rules)
    return {
        "parsed": parsed,
        "combined_review": combined_review,
        "candidate_rule_pairs": detailed,
        "rule_pairs_export": rule_pairs_export,
        "final_rules": final_rules,
        "risk_review": risk_review,
    }

# v6.1 - keep safe Python package rules through high-risk process gate
_v6_prev_enforce_high_risk_process_rules = enforce_high_risk_process_rules

def enforce_high_risk_process_rules(rules_df: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    if rules_df.empty or not getattr(settings, "enforce_high_risk_process_three_conditions", True):
        return rules_df
    min_conditions = int(getattr(settings, "high_risk_process_min_conditions", 3) or 3)
    rows = []
    for _, row in rules_df.iterrows():
        rd = row.to_dict()
        if is_safe_macos_python_two_condition_rule(rd):
            rows.append(rd)
            continue
        process_path = normalize_spaces(rd.get("Process Path"))
        if process_path and is_high_risk_process_path(process_path):
            if count_rule_conditions(rd) < min_conditions:
                continue
        rows.append(rd)
    return pd.DataFrame(rows, columns=rules_df.columns if not rules_df.empty else None)

# Rebind final builder so it uses the v6.1 high-risk gate.
def build_final_rules(candidate_pairs: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    rules_df = _v6_base_build_final_rules(candidate_pairs, settings)
    if rules_df.empty:
        return rules_df
    rules_df = filter_dangerous_rules(rules_df, settings)
    rules_df = enforce_high_risk_process_rules(rules_df, settings)
    final_columns = ["Path", "Certificate", "Process Path", "Created By"]
    for col in final_columns:
        if col not in rules_df.columns:
            rules_df[col] = None
    rules_df = rules_df[final_columns].copy()
    rules_df = normalize_final_rule_certificates(rules_df)
    return rules_df.drop_duplicates().dropna(how="all").reset_index(drop=True)

# v6.2 - fast final build/filter path for large Python exports

def filter_dangerous_rules(rules_df: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    if rules_df.empty:
        return rules_df
    df = sanitize_final_rule_values(rules_df) if "sanitize_final_rule_values" in globals() else rules_df.copy()
    rows = []
    for _, row in df.iterrows():
        rd = row.to_dict()
        path = normalize_spaces(rd.get("Path"))
        proc = normalize_spaces(rd.get("Process Path"))
        cond_count = count_rule_conditions(rd)
        if cond_count < 2:
            continue
        if is_invalid_process_condition(proc):
            rd["Process Path"] = None
            proc = None
            cond_count = count_rule_conditions(rd)
        if cond_count < 2:
            continue
        if is_safe_macos_python_two_condition_rule(rd):
            rows.append(rd)
            continue
        if is_dangerous_user_wildcard_rule(path) or is_overbroad_macos_path(path):
            continue
        if is_macos_user_writable_path(path) and cond_count < 3:
            continue
        if is_user_writable_path(path) and cond_count < 3:
            continue
        if proc and APPLE_PRIVATE_FRAMEWORK_PROCESS_RE.match(proc) and cond_count < 3:
            continue
        if proc and proc.startswith(("/users/", "/private/var/", "/var/folders/", "/tmp/", "/var/tmp/")) and cond_count < 3:
            continue
        rows.append(rd)
    return pd.DataFrame(rows, columns=df.columns if not df.empty else None)


def build_final_rules(candidate_pairs: pd.DataFrame, settings: RuleSettings) -> pd.DataFrame:
    if candidate_pairs.empty:
        return pd.DataFrame(columns=["Path", "Certificate", "Process Path", "Created By"])
    # Use the original pair-to-rule builder to avoid recursive v5/v6 guardrail calls on large exports.
    rules_df = _base_build_final_rules(candidate_pairs, settings)
    if rules_df.empty:
        return rules_df
    for col in ["Path", "Certificate", "Process Path", "Created By"]:
        if col not in rules_df.columns:
            rules_df[col] = None
    rules_df = normalize_final_rule_certificates(rules_df)
    rules_df = filter_dangerous_rules(rules_df, settings)
    rules_df = add_certificate_anchor_rules(rules_df, settings)
    rules_df = compress_language_folder_families(rules_df, settings)
    rules_df = compress_extension_families_global(rules_df, settings)
    rules_df = normalize_final_rule_certificates(rules_df)
    rules_df = suppress_covered_rules(rules_df)
    rules_df = filter_dangerous_rules(rules_df, settings)
    rules_df = enforce_high_risk_process_rules(rules_df, settings)
    final_columns = ["Path", "Certificate", "Process Path", "Created By"]
    for col in final_columns:
        if col not in rules_df.columns:
            rules_df[col] = None
    rules_df = rules_df[final_columns].copy()
    rules_df = normalize_final_rule_certificates(rules_df)
    return rules_df.drop_duplicates().dropna(how="all").reset_index(drop=True)

# v6.3 - avoid quadratic covered-rule suppression on very large Python exports
_v6_previous_suppress_covered_rules = suppress_covered_rules

def suppress_covered_rules(rules_df: pd.DataFrame) -> pd.DataFrame:
    if rules_df.empty or "Path" not in rules_df.columns:
        return rules_df
    # The precise pairwise suppression pass is O(n^2). On Python developer exports
    # with tens of thousands of native libraries, it can make tuning feel stalled.
    # Keep deterministic de-duping for large outputs and leave review to Risk Review.
    if len(rules_df) > 2000:
        return normalize_final_rule_certificates(rules_df).drop_duplicates().reset_index(drop=True)
    return _v6_previous_suppress_covered_rules(rules_df)

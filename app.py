import io
import json
import re
import time
from typing import Dict, List, Tuple

import pandas as pd
import math
import requests
import streamlit as st

# =========================
DEFAULT_BASE_URL = "https://api.cloud.hypatos.ai"
AUTH_PATH = "/v2/auth/token"
ENRICHMENT_INSERT_PATH = "/v2/enrichment/invoices"  # your existing invoices endpoint

# ---------- Auth helpers ----------

AUTH_PATH = "/v2/auth/token"  # keep your constant

def _pick_token_field(data: dict):
    # Try common token fields in order
    for k in ("token", "access_token", "id_token", "jwt", "bearer"):
        if k in data and data[k]:
            return data[k]
    return None

def get_token(base_url: str, client_id: str, client_secret: str, extra_headers: dict | None = None):
    """
    Try several auth payload/encoding variants to match what Postman may have done.
    Returns (ok: bool, token_or_error: str)
    """
    url = base_url.rstrip("/") + AUTH_PATH
    hdr_base = {"Accept": "application/json"}
    if extra_headers:
        hdr_base.update(extra_headers)

    attempts = []

    # 1) JSON body with camelCase keys
    attempts.append(dict(
        desc="JSON camelCase",
        kwargs=dict(
            url=url,
            headers={**hdr_base, "Content-Type": "application/json"},
            json={"clientId": client_id, "clientSecret": client_secret},
            timeout=30,
        ),
    ))

    # 2) JSON body with snake_case keys
    attempts.append(dict(
        desc="JSON snake_case",
        kwargs=dict(
            url=url,
            headers={**hdr_base, "Content-Type": "application/json"},
            json={"client_id": client_id, "client_secret": client_secret},
            timeout=30,
        ),
    ))

    # 3) Form-encoded OAuth-style
    attempts.append(dict(
        desc="FORM client_credentials",
        kwargs=dict(
            url=url,
            headers={**hdr_base, "Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            },
            timeout=30,
        ),
    ))

    # 4) Form-encoded with camelCase keys (some gateways accept this)
    attempts.append(dict(
        desc="FORM camelCase",
        kwargs=dict(
            url=url,
            headers={**hdr_base, "Content-Type": "application/x-www-form-urlencoded"},
            data={
                "clientId": client_id,
                "clientSecret": client_secret,
            },
            timeout=30,
        ),
    ))

    errors = []
    for att in attempts:
        try:
            resp = requests.post(**att["kwargs"])
            if resp.status_code < 300:
                data = resp.json() if resp.headers.get("Content-Type","").startswith("application/json") else {}
                token = _pick_token_field(data) or data.get("token")
                if token:
                    return True, token
                # if body wasn’t JSON, try to parse token from string (rare)
                if isinstance(resp.text, str) and len(resp.text) > 10 and "." in resp.text:
                    return True, resp.text.strip()
                errors.append(f"{att['desc']} OK but token missing: {data or resp.text[:300]}")
            else:
                # collect short diagnostic
                errors.append(
                    f"{att['desc']} -> {resp.status_code}: {resp.text[:300]}"
                )
        except Exception as e:
            errors.append(f"{att['desc']} exception: {e}")

    return False, "Auth failed. Tried variants:\n- " + "\n- ".join(errors)


def get_auth_headers(token: str, extra: Dict[str, str] = None) -> Dict[str, str]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    if extra:
        headers.update(extra)
    return headers

# ---------- Generic dataframe loading ----------
def load_table(uploaded_file) -> pd.DataFrame:
    """
    Reads CSV/XLSX strictly as strings to preserve leading zeros.
    - Strips header whitespace
    - Keeps empty cells as empty strings (not NaN)
    - Trims string cell whitespace
    - Safely removes a *leading* apostrophe only when it's the Excel text marker
      (e.g., "'00001" -> "00001"), without touching normal words like "'note".
    """
    name = uploaded_file.name.lower()
    if name.endswith(".csv"):
        df = pd.read_csv(
            uploaded_file,
            dtype=str,
            keep_default_na=False,  # don't auto-convert "" to NaN
            na_filter=False,
        )
    else:
        df = pd.read_excel(
            uploaded_file,
            dtype=str,              # force strings
            keep_default_na=False,  # keep "" not NaN
            engine="openpyxl" if name.endswith("xlsx") else None,
        )

    # normalize headers
    df.columns = [str(c).strip() for c in df.columns]

    def _normalize(val: str) -> str:
        if val is None:
            return ""
        if isinstance(val, str):
            v = val.strip()
            # If it starts with a single quote and what's after is digits, it's likely Excel's text marker
            if v.startswith("'") and v[1:].isdigit():
                return v[1:]
            return v
        # Numbers, bools, etc. -> stringify without losing leading zeros (we don't have them once it's numeric)
        # but dtype=str above should already prevent numeric parsing.
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
                return ""
            return str(val)
        return str(val)

    # apply to all cells
    df = df.applymap(_normalize)
    return df

def row_to_string_payload(row: pd.Series) -> dict:
    """
    Build a JSON-ready dict where:
    - Only non-empty values are included
    - Every value is a *string*
    """
    payload = {}
    for k, v in row.items():
        if v is None:
            continue
        s = str(v).strip()
        if s == "" or s.lower() == "nan":
            continue
        payload[k] = s
    return payload

def build_payloads(df: pd.DataFrame) -> list[dict]:
    return [row_to_string_payload(df.iloc[i]) for i in range(len(df))]

# ---------- Invoices page (existing behavior skeleton) ----------
def page_invoices(token: str, base_url: str):
    st.subheader("Upload Invoices (existing)")
    st.info("This keeps your current /v2/enrichment/invoices flow.")
    uploaded = st.file_uploader("CSV/Excel with invoice rows", type=["csv", "xlsx", "xls"])
    if not uploaded:
        return

    df = load_table(uploaded)
    st.write("Preview:", df.head())

    if st.button("Send to /v2/enrichment/invoices"):
        url = base_url.rstrip("/") + ENRICHMENT_INSERT_PATH
        headers = get_auth_headers(token)
        successes, failures = 0, 0
        results = []

        for i, row in df.iterrows():
            payload = row.dropna().to_dict()
            try:
                r = requests.post(url, headers=headers, json=payload, timeout=60)
                if r.status_code < 300:
                    successes += 1
                    results.append({"row": i, "status": "OK", "http": r.status_code})
                else:
                    failures += 1
                    results.append(
                        {"row": i, "status": "ERROR", "http": r.status_code, "body": r.text[:4000]}
                    )
            except Exception as e:
                failures += 1
                results.append({"row": i, "status": "ERROR", "http": "-", "body": str(e)})

        st.success(f"Done. OK: {successes}, Errors: {failures}")
        st.dataframe(pd.DataFrame(results))

# ---------- Lookup table page (NEW) ----------
def _slugify_type(name: str) -> str:
    """
    Lowercase, trim, replace spaces with underscores, and remove characters
    that are not letters, digits or underscore.
    """
    if not name:
        return ""
    s = name.strip().lower().replace(" ", "_")
    s = re.sub(r"[^a-z0-9_]", "", s)
    return s

def page_lookup_tables(token: str, base_url: str):
    st.subheader("Insert Lookup Table Rows")

    st.markdown(
        """
        1) Select the **lookup table type**  
        2) Upload **Excel/CSV** with columns like `externalId`, `key`, `description`, plus any extra fields.  
        All values are sent as **strings** (API requires strings).
        """
    )

    # ---- Type select with "custom" ----
    type_choice = st.selectbox(
        "Lookup table type (path param `{type}`)",
        options=["payment_terms", "tax_codes", "central_bank_indicator", "custom"],
        index=0,
        help="Choose a predefined type or 'custom' to provide your own.",
    )

    custom_type = ""
    if type_choice == "custom":
        raw_custom = st.text_input(
            "Custom lookup table type",
            placeholder="my_table",
            help="Allowed: letters, numbers, underscore. Spaces will become underscores.",
        )
        custom_type = _slugify_type(raw_custom)
        if raw_custom and not custom_type:
            st.error("Invalid custom type. Use only letters, numbers, or underscore.")
    lookup_type = custom_type if type_choice == "custom" else type_choice

    uploaded = st.file_uploader("Excel/CSV with rows to insert", type=["xlsx", "xls", "csv"])

    col_req, col_opt = st.columns(2)
    with col_req:
        st.caption("**Recommended columns**")
        st.code("externalId\nkey\ndescription", language="text")
    with col_opt:
        st.caption("**Optional columns**")
        st.text("Any others you add will be included as string fields.")

    validate_cols = st.checkbox("Validate recommended columns (`externalId`, `key`, `description`)", value=True)

    # Guard: need a lookup_type
    if type_choice == "custom" and not lookup_type:
        st.info("Enter a valid custom type to continue.")
        return

    if not lookup_type or not uploaded:
        return

    # ---- Load & show table (preserves leading zeros) ----
    df = load_table(uploaded)
    st.write("Preview (as strings, leading zeros preserved):")
    st.dataframe(df.head(20), use_container_width=True)

    # ---- Validate columns (optional) ----
    required = {"externalId", "key", "description"}
    if validate_cols:
        missing = [c for c in required if c not in df.columns]
        if missing:
            st.error(f"Missing columns: {', '.join(missing)}")
            return

    # ---- Build all-string payloads ----
    payloads = build_payloads(df)

    # ---- Payload preview ----
    st.markdown("#### Payload preview")
    preview_count = min(5, len(payloads))
    if preview_count == 0:
        st.warning("No non-empty rows found.")
        return

    st.caption(f"Showing first {preview_count} of {len(payloads)} payload(s).")
    st.code(json.dumps(payloads[:preview_count], indent=2, ensure_ascii=False), language="json")

    # ---- Endpoint target ----
    endpoint = f"{base_url.rstrip('/')}/v2/enrichment/lookup-tables/{lookup_type}"
    st.write("Target endpoint:", endpoint)

    throttle_ms = st.slider("Throttle between requests (ms)", min_value=0, max_value=2000, value=0, step=50)

    # ---- Send one request per row ----
    if st.button(f"Send {len(payloads)} request(s)"):
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        if st.session_state.get("extra_headers"):
            headers.update(st.session_state["extra_headers"])

        results = []
        ok = ko = 0
        progress = st.progress(0, text="Uploading rows...")

        for idx, payload in enumerate(payloads, start=1):
            try:
                resp = requests.post(endpoint, headers=headers, json=payload, timeout=60)
                if resp.status_code < 300:
                    ok += 1
                    results.append({"row": idx, "status": "OK", "http": resp.status_code})
                else:
                    ko += 1
                    results.append({"row": idx, "status": "ERROR", "http": resp.status_code, "body": resp.text[:2000]})
            except Exception as e:
                ko += 1
                results.append({"row": idx, "status": "ERROR", "http": "-", "body": str(e)})

            if throttle_ms:
                time.sleep(throttle_ms / 1000.0)

            progress.progress(int(idx * 100 / len(payloads)), text=f"Uploaded {idx}/{len(payloads)}")

        st.success(f"Finished. OK: {ok}, Errors: {ko}")
        st.dataframe(pd.DataFrame(results), use_container_width=True)

# ---------- Main App ----------
def main():
    import json
    import streamlit as st

    st.set_page_config(page_title="Hypatos Uploader", layout="wide")
    st.title("Hypatos Uploader")

    # ---- Sidebar: connection & routing ----
    with st.sidebar:
        st.header("Connection")

        base_url = st.text_input("Base URL", value=DEFAULT_BASE_URL)
        client_id = st.text_input("Client ID")
        client_secret = st.text_input("Client Secret", type="password")

        extra_headers_raw = st.text_area(
            "Extra headers (JSON, optional)",
            placeholder='{"X-Project-Id":"your-project-id"}',
            height=80,
        )
        extra_headers = None
        if extra_headers_raw.strip():
            try:
                extra_headers = json.loads(extra_headers_raw)
            except Exception as e:
                st.error(f"Invalid headers JSON: {e}")

        # Persist config for use in page functions if needed
        st.session_state["base_url"] = base_url
        st.session_state["extra_headers"] = extra_headers

        # Authenticate (or re-auth)
        if "auth_token" not in st.session_state:
            st.session_state.auth_token = None

        if st.button("Re-authenticate") or st.session_state.auth_token is None:
            if client_id and client_secret:
                ok, token_or_err = get_token(
                    base_url=base_url,
                    client_id=client_id,
                    client_secret=client_secret,
                    extra_headers=extra_headers,  # may be required by your gateway
                )
                if ok:
                    st.session_state.auth_token = token_or_err
                    st.success("Authenticated.")
                else:
                    st.session_state.auth_token = None
                    st.error(token_or_err)
            else:
                st.info("Enter Client ID and Client Secret, then click Re-authenticate.")

        st.divider()
        page = st.radio(
            "Select page",
            options=["Upload Invoices", "Lookup Tables"],
            index=0,
        )

    token = st.session_state.get("auth_token")
    if not token:
        st.info("Authenticate in the sidebar to continue.")
        return

    # ---- Route to selected page ----
    if page == "Upload Invoices":
        page_invoices(token=token, base_url=base_url)
    else:
        page_lookup_tables(token=token, base_url=base_url)


if __name__ == "__main__":
    main()

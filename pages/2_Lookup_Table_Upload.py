import os
import io
import json
import math
import time
import typing as t

import pandas as pd
import requests
import streamlit as st

# ---- Settings: pick these up from env (same as your existing app) ----
HYPATOS_BASE_URL = os.getenv("HYPATOS_BASE_URL", "").rstrip("/")
HYPATOS_TOKEN = os.getenv("HYPATOS_TOKEN")  # If you already mint tokens elsewhere
# Optional client-credentials fallbacks (only used if HYPATOS_TOKEN missing)
HYPATOS_OAUTH_TOKEN_URL = os.getenv("HYPATOS_OAUTH_TOKEN_URL", "")
HYPATOS_CLIENT_ID = os.getenv("HYPATOS_CLIENT_ID", "")
HYPATOS_CLIENT_SECRET = os.getenv("HYPATOS_CLIENT_SECRET", "")
HYPATOS_AUDIENCE = os.getenv("HYPATOS_AUDIENCE", "")  # if required by your IdP

st.set_page_config(page_title="Lookup Table Uploader", page_icon="🧩", layout="wide")

st.title("🧩 Insert rows into Hypatos Lookup Tables")
st.caption("Upload rows for any lookup table type (e.g., `payment_terms`).")

# -------------------- Auth helpers --------------------
@st.cache_data(show_spinner=False)
def get_bearer_token() -> str:
    """
    Returns a bearer token. Uses HYPATOS_TOKEN if provided.
    Otherwise tries client-credentials.
    """
    if HYPATOS_TOKEN:
        return HYPATOS_TOKEN

    if not (HYPATOS_OAUTH_TOKEN_URL and HYPATOS_CLIENT_ID and HYPATOS_CLIENT_SECRET):
        raise RuntimeError(
            "No HYPATOS_TOKEN and no client-credentials configured. "
            "Provide HYPATOS_TOKEN or set HYPATOS_OAUTH_TOKEN_URL, HYPATOS_CLIENT_ID, HYPATOS_CLIENT_SECRET."
        )
    data = {
        "grant_type": "client_credentials",
    }
    if HYPATOS_AUDIENCE:
        data["audience"] = HYPATOS_AUDIENCE

    resp = requests.post(
        HYPATOS_OAUTH_TOKEN_URL,
        data=data,
        auth=(HYPATOS_CLIENT_ID, HYPATOS_CLIENT_SECRET),
        timeout=30,
    )
    resp.raise_for_status()
    tok = resp.json().get("access_token")
    if not tok:
        raise RuntimeError("OAuth token endpoint returned no access_token.")
    return tok

def post_lookup_row(token: str, table_type: str, payload: dict) -> requests.Response:
    url = f"{HYPATOS_BASE_URL}/v2/enrichment/lookup-tables/{table_type}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    return requests.post(url, headers=headers, json=payload, timeout=60)

# -------------------- UI: inputs --------------------
with st.sidebar:
    st.header("Settings")
    table_type = st.text_input(
        "Lookup table type",
        placeholder="e.g. payment_terms",
        help="This becomes /v2/enrichment/lookup-tables/{type}",
    )
    dry_run = st.toggle("Dry-run (validate only, don’t POST)", value=True)
    chunk_size = st.number_input("Batch size (rows per request)", min_value=1, max_value=5000, value=100)
    stop_on_first_error = st.toggle("Stop on first error", value=False)

st.subheader("Upload file")
st.write("Accepted: **.xlsx**, **.xls**, **.csv**. First row must contain column names.")

uploaded = st.file_uploader("Choose file", type=["xlsx", "xls", "csv"])

template_cols = ["externalId", "key", "description"]
with st.expander("Template / Mapping", expanded=False):
    st.markdown(
        "- **Required columns**: `externalId`, `key` (depending on your table), recommended `description`.\n"
        "- **Any extra columns** in the file are sent as additional JSON fields.\n"
        "- Example JSON sent per row:\n"
        "```json\n"
        "{\n"
        '  "externalId": "12345",\n'
        '  "key": "someValue",\n'
        '  "description": "anotherValue",\n'
        '  "customField": "dynamicValue"\n'
        "}\n"
        "```"
    )

def read_dataframe(file) -> pd.DataFrame:
    if file.name.lower().endswith(".csv"):
        return pd.read_csv(file)
    # Excel
    data = file.read()
    return pd.read_excel(io.BytesIO(data), engine=None)

df: t.Optional[pd.DataFrame] = None
if uploaded:
    try:
        df = read_dataframe(uploaded)
        # Normalize headers (strip spaces)
        df.columns = [c.strip() for c in df.columns]
        st.success(f"Loaded {len(df):,} rows with columns: {list(df.columns)}")
        st.dataframe(df.head(20), use_container_width=True)
    except Exception as e:
        st.error(f"Failed to read file: {e}")

# -------------------- Validate & Upload --------------------
def row_to_payload(row: pd.Series) -> dict:
    # Core fields if present
    payload = {}
    for k in ["externalId", "key", "description"]:
        if k in row and pd.notna(row[k]):
            payload[k] = row[k]

    # Any additional columns become extra JSON properties
    for col in row.index:
        if col in payload:
            continue
        val = row[col]
        # Keep only non-null values
        if pd.notna(val):
            payload[str(col)] = val
    return payload

if st.button("Upload rows", type="primary", disabled=not (df is not None and table_type and HYPATOS_BASE_URL)):
    if not HYPATOS_BASE_URL:
        st.error("HYPATOS_BASE_URL is not set.")
    elif not table_type:
        st.error("Please enter a lookup table type.")
    elif df is None or df.empty:
        st.error("No data to upload.")
    else:
        try:
            token = get_bearer_token()
        except Exception as e:
            st.error(f"Auth error: {e}")
            st.stop()

        total = len(df)
        progress = st.progress(0)
        status_area = st.empty()
        results = []

        # Optional: basic checks for recommended columns
        missing = [c for c in ["externalId", "key"] if c not in df.columns]
        if missing:
            st.warning(
                f"Input missing recommended columns: {missing}. "
                "Rows will still be sent, but Hypatos may reject them depending on the table schema."
            )

        def chunks(iterable, n):
            for i in range(0, len(iterable), n):
                yield i, iterable[i:i+n]

        rows = df.to_dict(orient="records")
        errors = 0
        sent = 0

        for i, batch in chunks(rows, int(chunk_size)):
            payloads = [row_to_payload(pd.Series(r)) for r in batch]

            # Display a preview for this chunk
            with st.expander(f"Preview rows {i+1}–{i+len(batch)}", expanded=False):
                st.json(payloads, expanded=False)

            if dry_run:
                # Don't send; just simulate
                for p in payloads:
                    results.append({"row": sent + 1, "status": "DRY-RUN", "http": "-", "message": "-"})
                    sent += 1
            else:
                # POST one by one to capture per-row errors precisely
                for p in payloads:
                    try:
                        resp = post_lookup_row(token, table_type.strip(), p)
                        ok = 200 <= resp.status_code < 300
                        msg = "-"
                        if not ok:
                            try:
                                msg = json.dumps(resp.json())
                            except Exception:
                                msg = resp.text[:500]
                            errors += 1
                            if stop_on_first_error:
                                results.append({"row": sent + 1, "status": "ERROR", "http": resp.status_code, "message": msg})
                                raise RuntimeError(f"Stopped on first error at row {sent+1}: {msg}")
                        results.append({
                            "row": sent + 1,
                            "status": "OK" if ok else "ERROR",
                            "http": resp.status_code,
                            "message": msg,
                        })
                    except Exception as ex:
                        errors += 1
                        results.append({"row": sent + 1, "status": "ERROR", "http": "-", "message": str(ex)})
                        if stop_on_first_error:
                            raise
                    finally:
                        sent += 1

            progress.progress(min(1.0, sent / total))
            status_area.info(f"Processed {sent}/{total} rows • Errors so far: {errors}")

        st.success(f"Done. Sent {sent} rows. Errors: {errors}")
        st.download_button(
            "Download results as CSV",
            data=pd.DataFrame(results).to_csv(index=False).encode("utf-8"),
            file_name="lookup_upload_results.csv",
            mime="text/csv",
        )

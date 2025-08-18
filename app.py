import json
import csv
from collections import defaultdict
from decimal import Decimal, InvalidOperation
from datetime import datetime, timedelta
import requests
import streamlit as st

# =========================
# --- Settings (editable)
# =========================
DEFAULT_BASE_URL = "https://api.cloud.hypatos.ai"
AUTH_PATH = "/v2/auth/token"
ENRICHMENT_INSERT_PATH = "/v2/enrichment/invoices"

# =========================
# --- Utils
# =========================
def d(value):
    if value is None or str(value).strip() == "":
        return None
    try:
        return Decimal(str(value))
    except InvalidOperation:
        return None

def to_num(value):
    if value is None:
        return None
    if isinstance(value, Decimal):
        return float(value)
    try:
        return float(value)
    except Exception:
        return None

def clean_date(s):
    if not s or not str(s).strip():
        return None
    s = str(s).strip()
    for fmt in ("%Y-%m-%d", "%d.%m.%Y", "%Y/%m/%d", "%d/%m/%Y"):
        try:
            return datetime.strptime(s, fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    return s

def first_nonempty(*vals):
    for v in vals:
        if v is not None and str(v).strip() != "":
            return v
    return None

# =========================
# --- OAuth (Client Credentials)
# =========================
def get_access_token(base_url: str, client_id: str, client_secret: str, auth_path: str = "/v2/auth/token"):
    url = base_url.rstrip("/") + auth_path
    data = {"grant_type": "client_credentials"}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    resp = requests.post(url, data=data, headers=headers, auth=(client_id.strip(), client_secret.strip()), timeout=60)
    if resp.status_code != 200:
        raise RuntimeError(f"Token request failed: {resp.status_code} {resp.text}")

    payload = resp.json()
    access_token = payload.get("access_token")
    expires_in = payload.get("expires_in", 3600)

    if not access_token:
        raise RuntimeError(f"No access_token in response: {payload}")
    return access_token, datetime.utcnow() + timedelta(seconds=int(expires_in)), payload


def bearer_headers(token: str):
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

# =========================
# --- CSV -> Hypatos Payload
# =========================
def build_invoice_payload_from_rows(rows, overrides):
    first = rows[0]

    external_id = first.get("externalId") or overrides.get("external_id")
    if not external_id:
        raise ValueError("externalId is required (CSV column 'externalId' or provided in overrides).")

    payload = {
        "externalId": external_id,
        "externalClientId": first_nonempty(first.get("externalClientId"), overrides.get("external_client_id")),
        "documentId": first_nonempty(first.get("documentId"), overrides.get("document_id")),
        "documents": [],
        "supplierInvoiceNumber": first.get("supplierInvoiceNumber"),
        "invoiceNumber": first.get("invoiceNumber"),
        "externalCompanyId": first_nonempty(first.get("externalCompanyId"), overrides.get("external_company_id")),
        "externalSupplierId": first_nonempty(first.get("externalSupplierId"), overrides.get("external_supplier_id")),
        "externalBankAccountId": first.get("externalBankAccountId"),
        "fiscalYearLabel": first.get("fiscalYearLabel"),
        "issuedDate": clean_date(first.get("issuedDate")),
        "receivedDate": clean_date(first.get("receivedDate")),
        "postingDate": clean_date(first.get("postingDate")),
        "isCanceled": (str(first.get("isCanceled")).lower() == "true") if first.get("isCanceled") else None,
        "isCreditNote": (str(first.get("isCreditNote")).lower() == "true") if first.get("isCreditNote") else None,
        "externalCustomerId": first.get("externalCustomerId"),
        "relatedInvoice": first.get("relatedInvoice"),
        "currency": first_nonempty(first.get("currency"), overrides.get("currency")),
        "totalNetAmount": None,
        "totalFreightCharges": to_num(d(first.get("totalFreightCharges"))),
        "totalOtherCharges": to_num(d(first.get("totalOtherCharges"))),
        "totalTaxAmount": None,
        "totalGrossAmount": None,
        "paymentTerms": None,
        "externalApproverId": first.get("externalApproverId"),
        "customFields": {},
        "customMetadata": None,
        "headerText": first.get("headerText"),
        "type": first.get("type"),
        "invoiceLines": [],
        "withholdingTax": [],
        "documentType": first.get("documentType"),
    }

    if payload["documentId"]:
        payload["documents"] = [{"id": payload["documentId"], "type": "invoice"}]

    pt_key = first.get("paymentTermKey")
    pt_text = first.get("paymentTermText")
    pt_lang = first.get("paymentTermLanguage") or "en"
    if pt_key or pt_text:
        payload["paymentTerms"] = {
            "paymentTermKey": pt_key,
            "descriptions": [{"text": pt_text or "", "language": pt_lang}],
        }

    for k, v in first.items():
        if k.startswith("customFields."):
            payload["customFields"][k.split("customFields.", 1)[1]] = v

    cm = first.get("customMetadata")
    if cm:
        try:
            payload["customMetadata"] = json.loads(cm)
        except json.JSONDecodeError:
            pass

    if first.get("wht.key") or first.get("wht.amount") or first.get("wht.baseAmount"):
        wht = {
            "key": first.get("wht.key"),
            "baseAmount": to_num(d(first.get("wht.baseAmount"))),
            "amount": to_num(d(first.get("wht.amount"))),
            "currency": first_nonempty(first.get("wht.currency"), payload["currency"]),
        }
        payload["withholdingTax"].append(wht)

    sum_net = Decimal("0")
    sum_tax = Decimal("0")
    sum_gross = Decimal("0")

    for r in rows:
        line = {
            "externalId": r.get("line.externalId") or r.get("lineExternalId"),
            "externalCompanyId": first_nonempty(r.get("line.externalCompanyId"), payload["externalCompanyId"]),
            "type": r.get("line.type") or r.get("type"),
            "quantity": to_num(d(r.get("quantity"))),
            "netAmount": to_num(d(r.get("netAmount"))),
            "totalTaxAmount": to_num(d(r.get("totalTaxAmount"))),
            "grossAmount": to_num(d(r.get("grossAmount"))),
            "unitOfMeasure": r.get("unitOfMeasure"),
            "unitPrice": to_num(d(r.get("unitPrice"))),
            "taxCode": None,
            "taxJurisdictionCode": r.get("taxJurisdictionCode"),
            "itemText": r.get("itemText"),
            "externalPurchaseOrderId": r.get("externalPurchaseOrderId"),
            "purchaseOrderLineNumber": r.get("purchaseOrderLineNumber"),
            "centralBankIndicator": r.get("centralBankIndicator"),
            "customFields": {},
            "customMetadata": None,
            "accountAssignments": [],
        }

        tax_code = r.get("taxCode.code") or r.get("taxCodeCode")
        tax_desc = r.get("taxCode.description") or r.get("taxCodeDescription")
        if tax_code or tax_desc:
            line["taxCode"] = {"code": tax_code, "description": tax_desc}

        for k, v in r.items():
            if k.startswith("line.customFields."):
                line["customFields"][k.split("line.customFields.", 1)[1]] = v

        lcm = r.get("line.customMetadata")
        if lcm:
            try:
                line["customMetadata"] = json.loads(lcm)
            except json.JSONDecodeError:
                pass

        aa = {
            "externalGlAccountId": r.get("externalGlAccountId"),
            "externalCostCenterId": r.get("externalCostCenterId"),
            "glAccountCode": r.get("glAccountCode"),
            "costCenterCode": r.get("costCenterCode"),
            "quantity": to_num(d(r.get("aa.quantity"))),
            "externalProjectId": r.get("externalProjectId"),
            "externalOrderId": r.get("externalOrderId"),
            "costElementCode": r.get("costElementCode"),
        }
        if any(v is not None and str(v) != "" for v in aa.values()):
            line["accountAssignments"].append(aa)

        payload["invoiceLines"].append(line)

        if (nv := d(r.get("netAmount"))) is not None:
            sum_net += nv
        if (tv := d(r.get("totalTaxAmount"))) is not None:
            sum_tax += tv
        if (gv := d(r.get("grossAmount"))) is not None:
            sum_gross += gv

    payload["totalNetAmount"] = to_num(sum_net)
    payload["totalTaxAmount"] = to_num(sum_tax)

    if payload["totalFreightCharges"] is None:
        payload["totalFreightCharges"] = 0.0
    if payload["totalOtherCharges"] is None:
        payload["totalOtherCharges"] = 0.0
    if sum_gross:
        payload["totalGrossAmount"] = to_num(sum_gross)
    else:
        gross = sum_net + sum_tax + Decimal(str(payload["totalFreightCharges"])) + Decimal(str(payload["totalOtherCharges"]))
        payload["totalGrossAmount"] = to_num(gross)

    def prune(obj):
        if isinstance(obj, dict):
            return {k: prune(v) for k, v in obj.items() if v not in (None, {}, [], "")}
        if isinstance(obj, list):
            return [prune(x) for x in obj if x not in (None, {}, [], "")]
        return obj

    return prune(payload)

def read_csv_grouped_by_external_id(file_like):
    text = file_like.read().decode("utf-8")
    reader = csv.DictReader(text.splitlines())
    groups = defaultdict(list)
    for row in reader:
        ext = row.get("externalId") or row.get("invoiceExternalId")
        if not ext:
            raise ValueError("Each row must have 'externalId' (invoice header id).")
        groups[ext].append(row)
    return groups

# =========================
# --- Streamlit UI
# =========================
st.set_page_config(page_title="Hypatos Invoice Uploader", page_icon="🧾", layout="centered")

st.title("🧾 Hypatos Invoice Uploader")
st.caption("Upload a CSV of invoice lines → transform → POST to Hypatos Enrichment API")

with st.expander("API settings", expanded=False):
    base_url = st.text_input("Base URL", value=DEFAULT_BASE_URL, help="Change if your Hypatos tenant uses a different base.")
    endpoint_path = st.text_input("Insert endpoint path", value=ENRICHMENT_INSERT_PATH, help="POST target for inserting invoices.")
    auth_path = st.text_input("Auth token path", value=AUTH_PATH, help="OAuth2 client-credentials token endpoint.")

client_id = st.text_input("Client ID", type="default")
client_secret = st.text_input("Client Secret", type="password")
uploaded_csv = st.file_uploader("Upload CSV (invoice lines)", type=["csv"])

with st.expander("Optional header overrides (used if missing in CSV, or in Test Mode)"):
    override_external_client_id = st.text_input("externalClientId (fallback/test)", value="CLIENT-TEST")
    override_external_company_id = st.text_input("externalCompanyId (fallback/test)", value="COMPANY-TEST")
    override_external_supplier_id = st.text_input("externalSupplierId (fallback/test)", value="SUPPLIER-TEST")
    override_currency = st.text_input("currency (ISO 4217, e.g. EUR)", value="EUR")
    override_document_id = st.text_input("documentId", value="DOC-TEST-001")
    override_external_id = st.text_input("externalId (invoice id)", value="TEST-INVOICE-001")

test_mode = st.checkbox("Test without CSV (use only overrides & dummy line)", value=False)

dry_run = st.toggle("Dry run (do not POST, just preview JSON)", value=True)
pretty = st.toggle("Pretty-print JSON", value=True)

if "token" not in st.session_state:
    st.session_state.token = None
    st.session_state.token_expiry = datetime.utcnow()

def ensure_token():
    if not client_id or not client_secret:
        raise RuntimeError("Client ID and Client Secret are required.")
    # refresh if missing/expired (small skew)
    if (not st.session_state.token) or (datetime.utcnow() > st.session_state.token_expiry - timedelta(seconds=30)):
        token, exp = get_access_token(base_url, client_id, client_secret)
        st.session_state.token = token
        st.session_state.token_expiry = exp

col1, col2 = st.columns(2)
with col1:
    if st.button("🔑 Get Access Token"):
        try:
            token, exp, raw = get_access_token(base_url, client_id, client_secret, auth_path=auth_path)
            st.session_state.token = token
            st.session_state.token_expiry = exp
            st.success(f"Token acquired. Expires in ~{int((exp - datetime.utcnow()).total_seconds())}s.")
            st.code(json.dumps(raw, indent=2), language="json")
        except Exception as e:
            st.error(str(e))

with col2:
    if st.button("🚀 Transform & Send"):
        # Require either a CSV or test mode
        if not uploaded_csv and not test_mode:
            st.error("Please upload a CSV or enable 'Test without CSV'.")
            st.stop()

        # Prepare groups (either from CSV or using a single dummy row)
        if test_mode:
            # Build a minimal, valid dummy line from overrides
            dummy_row = {
                "externalId": (override_external_id or "TEST-INVOICE-001").strip() or "TEST-INVOICE-001",
                "externalClientId": (override_external_client_id or "").strip() or "CLIENT-TEST",
                "externalCompanyId": (override_external_company_id or "").strip() or "COMPANY-TEST",
                "externalSupplierId": (override_external_supplier_id or "").strip() or "SUPPLIER-TEST",
                "currency": (override_currency or "").strip() or "EUR",
                "documentId": (override_document_id or "").strip() or "DOC-TEST-001",
                "issuedDate": datetime.utcnow().strftime("%Y-%m-%d"),

                # --- line fields (single dummy line) ---
                "line.externalId": "LINE-1",
                "quantity": "1",
                "unitPrice": "100.00",
                "netAmount": "100.00",
                "totalTaxAmount": "19.00",
                "grossAmount": "119.00",
                "itemText": "Dummy service for testing"
            }
            groups = {dummy_row["externalId"]: [dummy_row]}
        else:
            try:
                groups = read_csv_grouped_by_external_id(uploaded_csv)
            except Exception as e:
                st.error(f"CSV error: {e}")
                st.stop()

        # Transform and (optionally) POST
        results = []
        for ext_id, rows in groups.items():
            # Build payload
            overrides = {
                "external_client_id": override_external_client_id or None,
                "external_company_id": override_external_company_id or None,
                "external_supplier_id": override_external_supplier_id or None,
                "currency": override_currency or None,
                "document_id": override_document_id or None,
                "external_id": override_external_id or None,
            }
            try:
                payload = build_invoice_payload_from_rows(rows, overrides)
            except Exception as e:
                results.append((ext_id, None, f"Build payload error: {e}", None))
                continue

            body = json.dumps(payload, indent=2) if pretty else json.dumps(payload)

            # Dry-run? Just show the JSON
            if dry_run:
                results.append((ext_id, 0, "Dry run: not sent", body))
                continue

            # POST to enrichment insert
            try:
                # Ensure we have a valid token
                ensure_token()
                url = base_url.rstrip("/") + endpoint_path
                resp = requests.post(url, headers=bearer_headers(st.session_state.token), data=body, timeout=60)
                try:
                    resp_body = json.dumps(resp.json(), indent=2)
                except Exception:
                    resp_body = resp.text
                results.append((ext_id, resp.status_code, None, resp_body))
            except Exception as e:
                results.append((ext_id, None, f"POST error: {e}", None))

        # Show results
        st.subheader("Results")
        for ext_id, status, err, body in results:
            with st.container(border=True):
                st.markdown(f"**externalId:** `{ext_id}`")
                if status is not None and status != 0:
                    st.markdown(f"**HTTP Status:** `{status}`")
                if err:
                    st.error(err)
                if body:
                    st.code(body, language="json")

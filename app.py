import json
import io, csv
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
    """Safely convert to Decimal or return None."""
    if value is None or str(value).strip() == "":
        return None
    try:
        return Decimal(str(value))
    except InvalidOperation:
        return None

def to_num(value):
    """Convert Decimal/str to float for JSON."""
    if value is None:
        return None
    if isinstance(value, Decimal):
        return float(value)
    try:
        return float(value)
    except Exception:
        return None

def clean_date(s):
    """Normalize to YYYY-MM-DD when possible."""
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
# --- Sample CSV helpers
# =========================
def _sample_rows(with_gl_cc: bool = False):
    """Two invoices: ext-1 (1 line), ext-2 (2 lines). Optionally include GL & Cost Center."""
    base_common_1 = {
        "externalId": "ext-1",
        "documentId": "686caa631bb57c4804f8a681",
        "supplierInvoiceNumber": "INV-001",
        "invoiceNumber": "1001",
        "externalCompanyId": "COMP-001",
        "externalSupplierId": "SUP-001",
        "currency": "EUR",
        "issuedDate": "2025-08-01",
        "line.externalId": "line-1",
        "quantity": "2",
        "unitPrice": "50.00",
        "netAmount": "100.00",
        "totalTaxAmount": "19.00",
        "grossAmount": "119.00",
        "itemText": "Consulting Service",
    }
    base_common_2_1 = {
        "externalId": "ext-2",
        "documentId": "686caa631bb57c4804f8a682",
        "supplierInvoiceNumber": "INV-002",
        "invoiceNumber": "1002",
        "externalCompanyId": "COMP-002",
        "externalSupplierId": "SUP-002",
        "currency": "USD",
        "issuedDate": "2025-08-05",
        "line.externalId": "line-1",
        "quantity": "5",
        "unitPrice": "20.00",
        "netAmount": "100.00",
        "totalTaxAmount": "10.00",
        "grossAmount": "110.00",
        "itemText": "Office Supplies",
    }
    base_common_2_2 = {
        "externalId": "ext-2",
        "documentId": "686caa631bb57c4804f8a682",
        "supplierInvoiceNumber": "INV-002",
        "invoiceNumber": "1002",
        "externalCompanyId": "COMP-002",
        "externalSupplierId": "SUP-002",
        "currency": "USD",
        "issuedDate": "2025-08-05",
        "line.externalId": "line-2",
        "quantity": "1",
        "unitPrice": "200.00",
        "netAmount": "200.00",
        "totalTaxAmount": "20.00",
        "grossAmount": "220.00",
        "itemText": "Software License",
    }

    if with_gl_cc:
        base_common_1.update({
            "externalGlAccountId": "GL-7000", "glAccountCode": "7000",
            "externalCostCenterId": "CC-100", "costCenterCode": "ADMIN-100",
        })
        base_common_2_1.update({
            "externalGlAccountId": "GL-4000", "glAccountCode": "4000",
            "externalCostCenterId": "CC-200", "costCenterCode": "OPS-200",
        })
        base_common_2_2.update({
            "externalGlAccountId": "GL-6500", "glAccountCode": "6500",
            "externalCostCenterId": "CC-300", "costCenterCode": "IT-300",
        })

    return [base_common_1, base_common_2_1, base_common_2_2]

def make_sample_csv_bytes(with_gl_cc: bool = False) -> bytes:
    """Basic sample (2 invoices / 3 lines)."""
    header = [
        "externalId","documentId","supplierInvoiceNumber","invoiceNumber",
        "externalCompanyId","externalSupplierId","currency","issuedDate",
        "line.externalId","quantity","unitPrice","netAmount","totalTaxAmount",
        "grossAmount","itemText",
        "externalGlAccountId","glAccountCode","externalCostCenterId","costCenterCode",
    ]
    rows = _sample_rows(with_gl_cc=with_gl_cc)
    sio = io.StringIO()
    writer = csv.DictWriter(sio, fieldnames=header, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        writer.writerow(r)
    return sio.getvalue().encode("utf-8")

def make_scenarios_csv_bytes() -> bytes:
    """
    Scenario CSV:
      - Scenario 1: FI invoice, 1 line (no PO fields)
      - Scenario 2: FI invoice, 2 lines (no PO fields, different GL & net)
      - Scenario 3: PO invoice, 1 line (no FI fields)
      - Scenario 4: PO invoice, 2 lines (no FI fields, different net amounts)
    All documentIds are 24-digit numeric.
    """
    def doc_id(n: int) -> str:
        return f"20250820{n:016d}"[:24]

    common_header = {
        "externalCompanyId": "COMP-DE-01",
        "externalSupplierId": "SUP-DE-01",
        "currency": "EUR",
        "issuedDate": "2025-08-10",
        "receivedDate": "2025-08-11",
        "postingDate": "2025-08-12",
        "isCanceled": "false",
        "isCreditNote": "false",
        "headerText": "Sample invoice for demo",
        "paymentTermKey": "NET30",
        "paymentTermText": "Net 30 days",
        "paymentTermLanguage": "en",
        "unitOfMeasure": "EA",
        "taxCode.code": "DEU_Standard",
        "taxCode.description": "DEU - Standard (19%)",
        "taxJurisdictionCode": "DEU",
    }

    rows = []

    # Scenario 1 — FI 1 line
    rows.append({
        **common_header,
        "externalId": "ext-fi-1",
        "documentId": doc_id(1),
        "supplierInvoiceNumber": "FINV-001",
        "invoiceNumber": "10001",
        "line.externalId": "line-1",
        "quantity": "2",
        "unitPrice": "50.00",
        "netAmount": "100.00",
        "totalTaxAmount": "19.00",
        "grossAmount": "119.00",
        "itemText": "Consulting Service",
        "externalGlAccountId": "GL-7000",
        "glAccountCode": "7000",
        "externalCostCenterId": "CC-100",
        "costCenterCode": "ADMIN-100",
    })

    # Scenario 2 — FI 2 lines
    rows.append({
        **common_header,
        "externalId": "ext-fi-2",
        "documentId": doc_id(2),
        "supplierInvoiceNumber": "FINV-002",
        "invoiceNumber": "10002",
        "line.externalId": "line-1",
        "quantity": "3",
        "unitPrice": "40.00",
        "netAmount": "120.00",
        "totalTaxAmount": "22.80",
        "grossAmount": "142.80",
        "itemText": "Hardware Components",
        "externalGlAccountId": "GL-4000",
        "glAccountCode": "4000",
        "externalCostCenterId": "CC-200",
        "costCenterCode": "OPS-200",
    })
    rows.append({
        **common_header,
        "externalId": "ext-fi-2",
        "documentId": doc_id(2),
        "supplierInvoiceNumber": "FINV-002",
        "invoiceNumber": "10002",
        "line.externalId": "line-2",
        "quantity": "5",
        "unitPrice": "40.00",
        "netAmount": "200.00",
        "totalTaxAmount": "38.00",
        "grossAmount": "238.00",
        "itemText": "Software Subscription",
        "externalGlAccountId": "GL-6500",
        "glAccountCode": "6500",
        "externalCostCenterId": "CC-300",
        "costCenterCode": "IT-300",
    })

    # Scenario 3 — PO 1 line
    rows.append({
        **common_header,
        "externalId": "ext-po-1",
        "documentId": doc_id(3),
        "supplierInvoiceNumber": "POINV-001",
        "invoiceNumber": "20001",
        "line.externalId": "line-1",
        "quantity": "3",
        "unitPrice": "50.00",
        "netAmount": "150.00",
        "totalTaxAmount": "28.50",
        "grossAmount": "178.50",
        "itemText": "Maintenance Service",
        "externalPurchaseOrderId": "4500000001",
        "purchaseOrderLineNumber": "00010",
    })

    # Scenario 4 — PO 2 lines
    rows.append({
        **common_header,
        "externalId": "ext-po-2",
        "documentId": doc_id(4),
        "supplierInvoiceNumber": "POINV-002",
        "invoiceNumber": "20002",
        "line.externalId": "line-1",
        "quantity": "4",
        "unitPrice": "20.00",
        "netAmount": "80.00",
        "totalTaxAmount": "15.20",
        "grossAmount": "95.20",
        "itemText": "Packaging Materials",
        "externalPurchaseOrderId": "4500000002",
        "purchaseOrderLineNumber": "00010",
    })
    rows.append({
        **common_header,
        "externalId": "ext-po-2",
        "documentId": doc_id(4),
        "supplierInvoiceNumber": "POINV-002",
        "invoiceNumber": "20002",
        "line.externalId": "line-2",
        "quantity": "10",
        "unitPrice": "23.00",
        "netAmount": "230.00",
        "totalTaxAmount": "43.70",
        "grossAmount": "273.70",
        "itemText": "Transport Service",
        "externalPurchaseOrderId": "4500000002",
        "purchaseOrderLineNumber": "00020",
    })

    header = [
        "externalId","documentId","supplierInvoiceNumber","invoiceNumber",
        "externalCompanyId","externalSupplierId","currency",
        "issuedDate","receivedDate","postingDate","isCanceled","isCreditNote",
        "headerText","paymentTermKey","paymentTermText","paymentTermLanguage",
        "unitOfMeasure","taxCode.code","taxCode.description","taxJurisdictionCode",
        "line.externalId","quantity","unitPrice","netAmount","totalTaxAmount","grossAmount","itemText",
        "externalGlAccountId","glAccountCode","externalCostCenterId","costCenterCode",
        "externalPurchaseOrderId","purchaseOrderLineNumber"
    ]

    sio = io.StringIO()
    writer = csv.DictWriter(sio, fieldnames=header, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        writer.writerow(r)
    return sio.getvalue().encode("utf-8")

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
def build_invoice_payload_from_rows(rows, overrides, header_tax_mode=False):
    """
    header_tax_mode=False (default): tax provided on line level -> sum to header, include on lines.
    header_tax_mode=True:  tax provided on header level     -> use first row's header tax, exclude line-level tax keys.
    """
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
        "totalTaxAmount": None,         # set later based on header_tax_mode
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

    # Payment terms
    pt_key = first.get("paymentTermKey")
    pt_text = first.get("paymentTermText")
    pt_lang = first.get("paymentTermLanguage") or "en"
    if pt_key or pt_text:
        payload["paymentTerms"] = {
            "paymentTermKey": pt_key,
            "descriptions": [{"text": pt_text or "", "language": pt_lang}],
        }

    # Header custom fields
    for k, v in first.items():
        if k.startswith("customFields."):
            payload["customFields"][k.split("customFields.", 1)[1]] = v

    # Header custom metadata
    cm = first.get("customMetadata")
    if cm:
        try:
            payload["customMetadata"] = json.loads(cm)
        except json.JSONDecodeError:
            pass

    # Withholding tax (optional)
    if first.get("wht.key") or first.get("wht.amount") or first.get("wht.baseAmount"):
        wht = {
            "key": first.get("wht.key"),
            "baseAmount": to_num(d(first.get("wht.baseAmount"))),
            "amount": to_num(d(first.get("wht.amount"))),
            "currency": first_nonempty(first.get("wht.currency"), payload["currency"]),
        }
        payload["withholdingTax"].append(wht)

    # Totals accumulation
    sum_net = Decimal("0")
    sum_tax = Decimal("0")  # only used in line-tax mode
    sum_gross = Decimal("0")

    for r in rows:
        line = {
            "externalId": r.get("line.externalId") or r.get("lineExternalId"),
            "externalCompanyId": first_nonempty(r.get("line.externalCompanyId"), payload["externalCompanyId"]),
            "type": r.get("line.type") or r.get("type"),
            "quantity": to_num(d(r.get("quantity"))),
            "netAmount": to_num(d(r.get("netAmount"))),
            # totalTaxAmount handled below (conditional on header_tax_mode)
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

        # Tax code on line
        tax_code = r.get("taxCode.code") or r.get("taxCodeCode")
        tax_desc = r.get("taxCode.description") or r.get("taxCodeDescription")
        if tax_code or tax_desc:
            line["taxCode"] = {"code": tax_code, "description": tax_desc}

        # Line custom fields/metadata
        for k, v in r.items():
            if k.startswith("line.customFields."):
                line["customFields"][k.split("line.customFields.", 1)[1]] = v
        lcm = r.get("line.customMetadata")
        if lcm:
            try:
                line["customMetadata"] = json.loads(lcm)
            except json.JSONDecodeError:
                pass

        # Account assignment on line (optional)
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

        # Totals accumulation (net / gross always; tax depends on mode)
        if (nv := d(r.get("netAmount"))) is not None:
            sum_net += nv
        if (gv := d(r.get("grossAmount"))) is not None:
            sum_gross += gv

        if not header_tax_mode:
            # Scenario 1: tax on lines -> include on line and sum to header
            line_tax_val = to_num(d(r.get("totalTaxAmount")))
            if line_tax_val is not None:
                line["totalTaxAmount"] = line_tax_val
            if (tv := d(r.get("totalTaxAmount"))) is not None:
                sum_tax += tv
        # else: header_tax_mode=True -> do NOT include line['totalTaxAmount']

        payload["invoiceLines"].append(line)

    # Final totals
    payload["totalNetAmount"] = to_num(sum_net)

    if header_tax_mode:
        # Scenario 2: header tax from first row only (do NOT sum)
        header_tax = to_num(d(first.get("totalTaxAmount")))
        payload["totalTaxAmount"] = header_tax
    else:
        payload["totalTaxAmount"] = to_num(sum_tax)

    if payload["totalFreightCharges"] is None:
        payload["totalFreightCharges"] = 0.0
    if payload["totalOtherCharges"] is None:
        payload["totalOtherCharges"] = 0.0

    if sum_gross:
        payload["totalGrossAmount"] = to_num(sum_gross)
    else:
        gross = sum_net + (d(payload["totalTaxAmount"]) or Decimal("0")) \
                + Decimal(str(payload["totalFreightCharges"])) \
                + Decimal(str(payload["totalOtherCharges"]))
        payload["totalGrossAmount"] = to_num(gross)

    # Prune empties
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

with st.expander("📥 Sample CSV downloads", expanded=False):
    basic_bytes = make_sample_csv_bytes(with_gl_cc=False)
    st.download_button(
        label="Download sample (basic, 2 invoices / 3 lines)",
        data=basic_bytes,
        file_name="sample_invoices.csv",
        mime="text/csv",
        use_container_width=True,
    )

    glcc_bytes = make_sample_csv_bytes(with_gl_cc=True)
    st.download_button(
        label="Download sample (with GL & Cost Center)",
        data=glcc_bytes,
        file_name="sample_invoices_with_gl_cc.csv",
        mime="text/csv",
        use_container_width=True,
    )

    scenarios_bytes = make_scenarios_csv_bytes()
    st.download_button(
        label="Download sample (scenario-rich: FI & PO cases)",
        data=scenarios_bytes,
        file_name="demo_invoices_scenarios.csv",
        mime="text/csv",
        use_container_width=True,
    )

with st.expander("Optional header overrides (used if missing in CSV, or in Test Mode)"):
    override_external_client_id = st.text_input("externalClientId (fallback/test)", value="CLIENT-TEST")
    override_external_company_id = st.text_input("externalCompanyId (fallback/test)", value="COMPANY-TEST")
    override_external_supplier_id = st.text_input("externalSupplierId (fallback/test)", value="SUPPLIER-TEST")
    override_currency = st.text_input("currency (ISO 4217, e.g. EUR)", value="EUR")
    override_document_id = st.text_input("documentId", value="DOC-TEST-001")
    override_external_id = st.text_input("externalId (invoice id)", value="TEST-INVOICE-001")

test_mode = st.checkbox("Test without CSV (use only overrides & dummy line)", value=False)

# Tax mode toggle (NEW)
header_tax_mode = st.toggle(
    "Provide total tax at header (ignore per-line 'totalTaxAmount')",
    value=False,
    help=(
        "OFF = Read tax on each line and sum to header. "
        "ON = Read 'totalTaxAmount' once from the first row and do NOT include "
        "'totalTaxAmount' on invoice lines in the payload."
    ),
)

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
        token, exp, _ = get_access_token(base_url, client_id, client_secret, auth_path=auth_path)
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
                "totalTaxAmount": "19.00",   # used only if header_tax_mode == False
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
            overrides = {
                "external_client_id": override_external_client_id or None,
                "external_company_id": override_external_company_id or None,
                "external_supplier_id": override_external_supplier_id or None,
                "currency": override_currency or None,
                "document_id": override_document_id or None,
                "external_id": override_external_id or None,
            }
            try:
                payload = build_invoice_payload_from_rows(rows, overrides, header_tax_mode=header_tax_mode)
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

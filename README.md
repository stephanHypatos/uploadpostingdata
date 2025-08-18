# Hypatos Invoice Uploader 🧾

A simple **Streamlit web app** that lets you upload (or simulate) invoice data and send it directly to the **Hypatos Enrichment API**.

---

## 🌟 What this app does

- **Authenticate** with Hypatos via *Client ID* and *Client Secret* (OAuth2 Client Credentials).  
- **Upload a CSV** of invoice lines **or** use a **test mode** with manual values (no CSV needed).  
- **Transform the data** into the exact JSON format required by Hypatos.  
- **Send invoices** to Hypatos’ Enrichment API with one click.  
- **Preview results** (dry-run mode lets you see the JSON before sending).  

In short:  
> The app saves you from manually building JSON payloads or running Postman collections — just upload a file or fill in a few fields, and the app takes care of the rest.

---

## 🖥️ How to use

1. **Launch the app** (Streamlit Cloud or local).  
2. **Enter your Hypatos Client ID and Client Secret**.  
3. Choose one of two options:
   - Upload a **CSV file** containing invoice lines, **or**  
   - Tick **“Test without CSV”** to generate a dummy invoice from override fields.  
4. (Optional) Fill in **header override fields** (e.g. supplier, company, currency).  
5. Click **🔑 Get Access Token** to authenticate.  
6. Click **🚀 Transform & Send** to preview or send the invoice payload.  
7. Review the **results panel** to see HTTP responses and JSON data.

---

## 📂 Example CSV structure

Each row in the CSV represents one invoice line. Important columns include:

- `externalId` → invoice identifier  
- `netAmount`, `grossAmount`, `totalTaxAmount` → amounts per line  
- `quantity`, `unitPrice` → line details  
- `itemText` → description  

The app groups rows by `externalId` to build complete invoices.

👉 If you don’t have a CSV yet, just use **Test Mode** — the app will generate a valid dummy invoice.

---

## ⚙️ Deployment

### Requirements

Create a `requirements.txt` with:

```txt
streamlit>=1.36.0
requests>=2.32.0

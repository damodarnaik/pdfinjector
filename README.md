# PDF-Injector

**pdfinjector** is a tool designed for penetration testers and bug bounty hunters. It automates the creation of malicious PDF artifacts to test for **Cross-Site Scripting (XSS)** and **Server-Side Request Forgery (SSRF)** vulnerabilities in PDF processing pipelines.

Unlike simple append scripts, pdfinjector uses a **Context-Aware Payload Engine** to analyze your input and automatically translate standard web JavaScript (e.g., `fetch`, `alert`) into Adobe's proprietary AcroJS syntax (`submitForm`, `app.alert`), ensuring high success rates against real-world targets.

## ⚡ Features

* **Smart Payload Translation**: Automatically converts `alert()` to `app.alert()` and `fetch()` to `this.submitForm()`.
* **Poly-Protocol SSRF**: Generates "noisy" SSRF payloads that try multiple methods (FDF, HTML, SOAP) simultaneously to maximize the chance of a callback.
* **/OpenAction Execution**: Injects payloads directly into the PDF Catalog to trigger immediately upon opening.
* **Metadata Preservation**: Keeps original PDF metadata to mimic legitimate documents.
* **Stealth & Resilience**: Rebuilds the PDF structure cleanly using `pypdf` to prevent file corruption errors.

---

## 📦 Installation

pdfinjector is built on Python 3 and relies on the robust `pypdf` library for object manipulation.

```bash
# Clone the repository
git clone https://github.com/damodarnaik/pdfinjector.git
cd pdfinjector

# Install dependencies
pip install pypdf
```

---

## 🚀 Usage

```bash
python pdfinjector.py -i <INPUT_PDF> -o <OUTPUT_PDF> [MODE]
```

#### Arguments

| Argument | Description |
|----------|----------|
| ``` -i ```, ``` --input ```   | Path to the clean, source PDF file (required).   |
| ``` -o ```, ``` --output ```   | Path to save the injected malicious PDF (required).   |
| ``` -p ```, ``` --payload ```   | Path to a text file containing your custom JavaScript payload.   |
| --ssrf   | Quick Mode: Generates a Poly-Protocol SSRF payload targeting the provided URL (No payload file needed).   |

---

## 📖 Examples

### 1. The "Quick XSS" Test

You have a standard XSS payload in a text file (payload.txt). pdfinjector will detect standard JS and convert it for PDF compatibility.

#### payload.txt:

```javascript
alert('XSS Check: ' + document.location);
```

#### Command:

```bash
python pdfinjector.py -i input_file.pdf -o xss_poc.pdf -p payload.txt
```

**Result:** The tool converts alert to app.alert and injects it. When opened, a popup appears.

### 2. Testing for SSRF (Poly-Protocol)

Use this to test if the PDF parser (e.g., Adobe Reader, Backend Bot) allows outbound network connections via JavaScript. This mode attempts submitForm (FDF), submitForm (HTML), and SOAP.connect in sequence.
```bash
python pdfinjector.py -i input_file.pdf -o ssrf_test.pdf --ssrf http://burp-collaborator.net
```

**Result:** pdfinjector generates a script that fires multiple requests to your listener. If any method is allowed by the viewer, you will get a hit.

---

## 🛠 Technical Details

### The Translation Engine

PDFs do not run in a browser DOM (Document Object Model). They run in the Acrobat API environment. Apex handles this difference automatically:

| Web JS Input | Translated AcroJS | Purpose |
|----------|----------|----------|
| ``` Ralert('x') ```     | ``` app.alert('x') ```   | Visual Proof of Concept  |
| ``` fetch('url') ```   | ``` this.submitForm({cURL: 'url'}) ```   | Network/SSRF  |
| ``` window.location ```   | ``` app.launchURL('url') ```   | Redirection  |

### Injection Vector

pdfinjector targets the Document Catalog's ``` /OpenAction ``` dictionary.
1. It reads the input PDF structure using ``` pypdf ```.
2. It uses ``` writer.add_js() ``` to attach the script to the root catalog.
3. This ensures the payload executes automatically when the document is loaded, without requiring the user to click a button.

---

## ⚠️ Disclaimer

**pdfinjector is provided for educational and authorized testing purposes only.** The authors are not responsible for any misuse of this tool. Do not use this tool on systems you do not have explicit permission to test. Always adhere to the scope of your engagement or Bug Bounty program.

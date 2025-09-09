import re
import tldextract
import pandas as pd
import os
from email import message_from_file



def load_reference_data(file_path):
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError

        file_extension = os.path.splitext(file_path)
        data = []

        if file_extension == '.txt':
            with open(file_path, 'r', encoding='utf-8') as f:
                data = [line.strip() for line in f if line.strip()]
        elif file_extension == '.csv':
            df = pd.read_csv(file_path, header=0, on_bad_lines='skip')
            first_column_name = df.columns[0]
            data = df[first_column_name].dropna().astype(str).tolist()
        elif file_extension in ['.xlsx', '.xls']:
            df = pd.read_excel(file_path, header=0, engine='openpyxl')
            first_column_name = df.columns[0]
            data = df[first_column_name].dropna().astype(str).tolist()
        else:
            print(f"Warning: Unsupported file type '{file_extension}' for {file_path}")

        return data

    except FileNotFoundError:
        print(f"Error: File not found at '{file_path}'")
        return []
    except Exception as e:
        print(f"An error occurred while reading {file_path}: {e}")
        return []


def grade_email(keywords, words_in_email):
    keyword_set = set(keywords)
    words_in_email_set = set(words_in_email)
    matched_keywords = keyword_set.intersection(words_in_email_set)
    return {
        'score': len(matched_keywords),
        'matched_keywords': list(matched_keywords)
    }


def find_ip_links(email_content, suspicious_ips):
    findings = {}
    score = 0
    ip_url_pattern = r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    found_ip_urls = re.findall(ip_url_pattern, email_content)

    if not found_ip_urls:
        return {'technical_score': 0}

    matched_ips = []
    for url in found_ip_urls:
        ip_address = url.split('//')[1]
        if ip_address in suspicious_ips:
            matched_ips.append(ip_address)

    if matched_ips:
        findings['matched_ips'] = matched_ips
        score += len(matched_ips) * 3

    findings['technical_score'] = score
    return findings


def domain_find(email_content, suspicious_domains):
    findings = {}
    score = 0
    url_pattern = r'https?://[^\s"\'<>]+'
    found_urls = re.findall(url_pattern, email_content)

    if not found_urls:
        return {'domain_score': 0}

    matched_domains = []
    for url in found_urls:
        try:
            extracted_domain = tldextract.extract(url).top_domain_under_public_suffix
            if extracted_domain and extracted_domain in suspicious_domains:
                matched_domains.append(extracted_domain)
        except Exception:
            continue

    if matched_domains:
        unique_matched_domains = list(set(matched_domains))
        findings['matched_domains'] = unique_matched_domains
        score += len(unique_matched_domains) * 2

    findings['domain_score'] = score
    return findings


def links_find(email_content, suspicious_links):
    findings = {}
    score = 0
    link_text_pattern = r'<a[^>]*>(.*?)</a>'
    found_texts = re.findall(link_text_pattern, email_content, re.IGNORECASE)

    if not found_texts:
        return {'link_text_score': 0}

    matched_texts = []
    for text in found_texts:
        clean_text = text.strip().lower()
        if clean_text in suspicious_links:
            matched_texts.append(text)

    if matched_texts:
        unique_matched_texts = list(set(matched_texts))
        findings['matched_link_texts'] = unique_matched_texts
        score += len(unique_matched_texts)

    findings['link_text_score'] = score
    return findings


def check_for_url_mismatch(email_content):
    findings = {}
    score = 0
    mismatched_links = []
    link_pattern = r'<a\s+href=["\'](https?://.*?)["\'][^>]*>(.*?)</a>'
    found_links = re.findall(link_pattern, email_content, re.IGNORECASE)

    for href_url, link_text in found_links:
        clean_text = link_text.strip()
        if not clean_text or not href_url:
            continue

        try:
            href_domain = tldextract.extract(href_url).top_domain_under_public_suffix
            text_domain = tldextract.extract(clean_text).top_domain_under_public_suffix

            if text_domain and href_domain != text_domain:
                mismatched_links.append({
                    'visible_text': clean_text,
                    'actual_destination': href_url
                })
                score += 3
        except Exception:
            continue

    if mismatched_links:
        findings['mismatched_links'] = mismatched_links

    findings['mismatch_score'] = score
    return findings


def analyze_email_headers(email_message):
    findings = {}
    score = 0
    from_header = email_message.get('From', '')
    return_path_header = email_message.get('Return-Path', '')

    from_email_match = re.search(r'<(.+?)>', from_header)
    return_path_match = re.search(r'<(.+?)>', return_path_header)

    if from_email_match and return_path_match and from_email_match.group(1) != return_path_match.group(1):
        score += 10
        findings['sender_spoofing'] = {
            'from': from_email_match.group(1),
            'return_path': return_path_match.group(1)
        }

    auth_results = email_message.get('Authentication-Results', '').lower()
    if 'spf=fail' in auth_results:
        score += 10
        findings['spf_check'] = 'Fail'
    if 'dkim=fail' in auth_results:
        score += 10
        findings['dkim_check'] = 'Fail'

    return {'score': score, 'findings': findings}


def export_findings_to_excel(report_data, output_file="phishing_report.xlsx"):
    data_rows = []
    for result in report_data:
        mismatched = result['mismatches'].get('mismatched_links', [])
        data_rows.append({
            "Email File": result.get('email_file', 'N/A'),
            "Risk Level": result.get('risk_level', ''),
            "Total Score": result.get('total_score', 0),
            "Matched Keywords": ", ".join(result['keywords'].get('matched_keywords', [])),
            "Matched IPs in URLs": ", ".join(result['ip_urls'].get('matched_ips', [])),
            "Matched Suspicious Domains": ", ".join(result['domains'].get('matched_domains', [])),
            "Matched Suspicious Link Texts": ", ".join(result['link_texts'].get('matched_link_texts', [])),
            "Mismatched Links (Visible -> Actual)": ", ".join(
                [f"'{m['visible_text']}' -> '{m['actual_destination']}'" for m in mismatched]
            ),
            "Header Issues": ", ".join(result['headers'].get('findings', {}).keys())
        })
    df = pd.DataFrame(data_rows)
    df.to_excel(output_file, index=False)
    print(f"\nExcel report saved to {output_file}")


def main():
    keyword_file = "KEYWORDS.xlsx"
    suspicious_ips_file = "phishing-IPs-ACTIVE.txt"
    suspicious_domains_file = "phishing-domains-ACTIVE.txt"
    suspicious_links_file = "phishing-links-ACTIVE.txt"
    output_file = "phishing_analysis_report.xlsx"

    user_input = input("Please enter the email filenames, separated by commas (EX: a.eml, b.eml): ")
    email_files = [filename.strip() for filename in user_input.split(',')]

    for email_file in email_files:
        print(f"Processing: {email_file}")

    print("Loading reference data...")

    keywords = load_reference_data(keyword_file)
    suspicious_ips = load_reference_data(suspicious_ips_file)
    suspicious_domains = load_reference_data(suspicious_domains_file)
    suspicious_links = load_reference_data(suspicious_links_file)

    if not all([keywords, suspicious_ips, suspicious_domains, suspicious_links]):
        print("Could not load one or more reference files. Exiting.")
        return

    all_reports = []

    for email_file in email_files:
        if not os.path.exists(email_file):
            print(f"Warning: Email file not found, skipping: {email_file}")
            continue

        print(f"\n--- Analyzing: {email_file} ---")

        with open(email_file, 'r', encoding='utf-8', errors='ignore') as f:
            msg = message_from_file(f)

        email_body = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if "text/plain" in content_type or "text/html" in content_type:
                    email_body = part.get_payload(decode=True).decode(errors='ignore')
                    break
        else:
            email_body = msg.get_payload(decode=True).decode(errors='ignore')

        words_in_email = re.split(r'\s+', email_body.lower())

        keyword_results = grade_email(keywords, words_in_email)
        links_results = links_find(email_body, suspicious_links)
        ip_results = find_ip_links(email_body, suspicious_ips)
        domain_results = domain_find(email_body, suspicious_domains)
        mismatch_results = check_for_url_mismatch(email_body)
        header_results = analyze_email_headers(msg)

        total_score = (
                keyword_results.get('score', 0) +
                links_results.get('link_text_score', 0) +
                ip_results.get('technical_score', 0) +
                domain_results.get('domain_score', 0) +
                mismatch_results.get('mismatch_score', 0) +
                header_results.get('score', 0)
        )

        risk_level = "Low"
        if 15 <= total_score < 25:
            risk_level = "Medium"
        elif 25 <= total_score < 50:
            risk_level = "High"
        elif total_score >= 50:
            risk_level = "Critical"

        print(f"Total Score: {total_score} | Risk Level: {risk_level}")

        report = {
            'email_file': email_file,
            'total_score': total_score,
            'risk_level': risk_level,
            'keywords': keyword_results,
            'ip_urls': ip_results,
            'domains': domain_results,
            'link_texts': links_results,
            'mismatches': mismatch_results,
            'headers': header_results
        }
        all_reports.append(report)

    if all_reports:
        export_findings_to_excel(all_reports, output_file)


if __name__ == "__main__":
    main()
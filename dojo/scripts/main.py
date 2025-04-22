from lib.create_users_and_products import (
    process_findings_from_file,
    process_users_from_file,
)
from lib.encrypting_reports import anonymize_report
from lib.partitioning_findings import split_findings
from lib.send_emails import send_emails


def confirm(message):
    response = input(f"{message} (y/n): ").strip().lower()
    return response == "y"


def step(title, func, *args):
    print(f"\n- Step: {title}")
    if confirm("Do you want to run this step?"):
        func(*args)
    else:
        print(f"Step '{title}' skipped.")


def main():
    print("==== Orchestration Flow - DefectDojo Crivo ====")
    step(
        "1. Create users and associate with products",
        process_users_from_file,
        "data/inputs/users.txt",
    )
    step(
        "2. Anonymize OpenVAS report",
        anonymize_report,
        "data/inputs/openvas_raw.xml",
        "data/inputs/openvas_anon.xml",
    )
    step(
        "3. Split vulnerabilities among products",
        split_findings,
        "data/inputs/openvas_anon.xml",
    )
    step(
        "4. Import findings into products",
        process_findings_from_file,
        "data/inputs/findings.txt",
    )
    step("5. Send emails with credentials", send_emails)
    print("\nScript completed.")


if __name__ == "__main__":
    main()

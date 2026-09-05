import os
import shutil

import fitz


def extract_assets():
    pdf_path = r"e:\downloads\Shyam_Kumar_D_AEGIS_Project_Report_Dark.pdf"
    if not os.path.exists(pdf_path):
        pdf_path = r"e:\downloads\Shyam_Kumar_D_AEGIS_Project_Report_Dark_compressed.pdf"

    out_dir = os.path.join("docs", "assets", "screenshots")
    os.makedirs(out_dir, exist_ok=True)

    # Also copy the PDF into docs/
    pdf_dest = os.path.join("docs", "AEGIS_Project_Report.pdf")
    shutil.copyfile(pdf_path, pdf_dest)
    print(f"Copied report PDF to {pdf_dest}")

    doc = fitz.open(pdf_path)
    mapping = [
        (4, "01_eventbridge_autonomous_scheduler.png"),
        (5, "02_autonomous_succeeded_executions.png"),
        (6, "03_purple_team_7_stage_workflow_graph.png"),
        (7, "04_soar_containment_orchestrator_decision_tree.png"),
        (8, "05_dynamodb_remediation_idempotency_table.png"),
        (9, "06_dynamodb_attack_metrics_execution_history.png"),
        (10, "07_s3_forensics_vault_worm_object_lock.png"),
        (11, "08_s3_sealed_forensic_evidence_artifacts.png"),
        (12, "09_aws_kms_customer_managed_keys.png"),
        (13, "10_eventbridge_custom_security_bus.png"),
        (14, "11_sqs_dead_letter_queue.png"),
        (15, "12_cloudwatch_log_groups.png"),
        (16, "13_iam_target_test_identity_isolation_tags.png"),
        (17, "14_war_room_api_gateway_cognito_auth.png"),
        (18, "15_live_attack_scenarios_8_of_8_passed.png"),
        (19, "16_full_unit_test_suite_110_passed.png"),
    ]

    for page_num, fname in mapping:
        page = doc[page_num - 1]
        images = page.get_images()
        if images:
            xref = images[0][0]
            base_img = doc.extract_image(xref)
            image_bytes = base_img["image"]
            out_path = os.path.join(out_dir, fname)
            with open(out_path, "wb") as f:
                f.write(image_bytes)
            print(
                f"Extracted {fname} ({len(image_bytes)} bytes, {base_img['width']}x{base_img['height']})"
            )
        else:
            print(f"No image on page {page_num}")


if __name__ == "__main__":
    extract_assets()

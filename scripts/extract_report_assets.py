import io
import os
import shutil

import fitz
from PIL import Image


def extract_assets():
    # Prefer the latest uploaded upgraded PDF
    candidates = [
        r"e:\downloads\Shyam_Kumar_D_AEGIS_Project_Report_Dark (2).pdf",
        r"e:\downloads\Shyam_Kumar_D_AEGIS_Project_Report_Dark (1).pdf",
        r"e:\downloads\Shyam_Kumar_D_AEGIS_Project_Report_Dark.pdf",
    ]
    pdf_path = None
    for candidate in candidates:
        if os.path.exists(candidate):
            pdf_path = candidate
            break

    if not pdf_path:
        raise FileNotFoundError("Could not find upgraded project report PDF.")

    print(f"Loading upgraded PDF from: {pdf_path}")

    out_dir = os.path.join("docs", "assets", "screenshots")
    os.makedirs(out_dir, exist_ok=True)

    # Replace docs/AEGIS_Project_Report.pdf with upgraded PDF
    pdf_dest = os.path.join("docs", "AEGIS_Project_Report.pdf")
    shutil.copyfile(pdf_path, pdf_dest)
    print(f"Replaced report PDF at: {pdf_dest} ({os.path.getsize(pdf_dest)} bytes)")

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

            # Load into PIL to ensure clean conversion to high-resolution PNG
            img = Image.open(io.BytesIO(image_bytes))
            out_path = os.path.join(out_dir, fname)
            img.save(out_path, format="PNG", optimize=True)
            print(
                f"Successfully replaced {fname}: {img.width}x{img.height} PNG ({os.path.getsize(out_path)} bytes)"
            )
        else:
            print(f"Warning: No image found on page {page_num}")


if __name__ == "__main__":
    extract_assets()

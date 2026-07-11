from cfn_risk_mapper.report_generator import generate_report

_BROAD_ROLE_FINDING = {
    "check_id": "CKV_AWS_63",
    "check_name": 'Ensure no IAM policies documents allow "*" as a statement\'s actions',
    "resource_type": "AWS::IAM::Role",
    "logical_id": "BroadRole",
    "file_path": "/fixtures/sample.json",
    "file_line_range": [5, 36],
    "declared_exposure_score": 8.5,
    "controls": ["AC-6"],
}
_DATA_BUCKET_FINDING = {
    "check_id": "CKV_AWS_20",
    "check_name": "Ensure the S3 bucket does not allow READ permissions to everyone",
    "resource_type": "AWS::S3::Bucket",
    "logical_id": "DataBucket",
    "file_path": "/fixtures/sample.json",
    "file_line_range": [37, 42],
    "declared_exposure_score": 7.0,
    "controls": ["AC-3"],
}
_LOW_SCORE_SAME_FAMILY_FINDING = {
    "check_id": "CKV_AWS_53",
    "check_name": "Ensure S3 bucket has block public ACLs enabled",
    "resource_type": "AWS::S3::Bucket",
    "logical_id": "DataBucket",
    "file_path": "/fixtures/sample.json",
    "file_line_range": [37, 42],
    "declared_exposure_score": 3.0,
    "controls": ["AC-3"],
}
_IA_FAMILY_FINDING = {
    "check_id": "CKV_AWS_161",
    "check_name": "Ensure RDS database has IAM authentication enabled",
    "resource_type": "AWS::RDS::DBInstance",
    "logical_id": "SomeDatabase",
    "file_path": "/fixtures/sample.json",
    "file_line_range": [1, 4],
    "declared_exposure_score": 5.0,
    "controls": ["IA-2"],
}
_UNMAPPED_FINDING = {
    "check_id": "CKV_AWS_999",
    "check_name": "Some check with no mapping yet",
    "resource_type": "AWS::Lambda::Function",
    "logical_id": "ProcessorFunction",
    "file_path": "/fixtures/sample.json",
    "file_line_range": [43, 66],
    "declared_exposure_score": 4.0,
    "controls": [],
}


def test_generate_report_groups_by_control_family_and_ranks_by_score(tmp_path):
    out_path = tmp_path / "report.md"
    findings = [
        _DATA_BUCKET_FINDING,
        _LOW_SCORE_SAME_FAMILY_FINDING,
        _BROAD_ROLE_FINDING,
        _IA_FAMILY_FINDING,
    ]

    generate_report(findings, out_path, template_path="fixtures/sample.json")

    text = out_path.read_text()
    ac_heading_pos = text.index("## AC -- Access Control")
    ia_heading_pos = text.index("## IA -- Identification and Authentication")
    broad_role_pos = text.index("CKV_AWS_63")
    data_bucket_pos = text.index("CKV_AWS_20")
    low_score_pos = text.index("CKV_AWS_53")

    assert "Total findings: 4" in text
    # AC-3 and AC-6 are both in the AC family, and AC sorts before IA.
    assert ac_heading_pos < ia_heading_pos
    # Within the AC group, findings rank by score: 8.5, then 7.0, then 3.0.
    assert broad_role_pos < data_bucket_pos < low_score_pos


def test_generate_report_lists_unmapped_findings_separately(tmp_path):
    out_path = tmp_path / "report.md"

    generate_report([_UNMAPPED_FINDING], out_path)

    text = out_path.read_text()
    assert "Unmapped findings" in text
    assert "CKV_AWS_999" in text


def test_generate_report_includes_declared_exposure_disclaimer(tmp_path):
    out_path = tmp_path / "report.md"

    generate_report([_BROAD_ROLE_FINDING], out_path)

    text = out_path.read_text()
    assert "not live AWS state" in text

# SPDX-License-Identifier: Apache-2.0
"""What counts as a provider call, and which files the local closure must and must not contain."""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ENTRY = "scripts/local_gate.sh"

#: What one file contributes to the closure: (findings, repository files it reaches).
Result = tuple[list[str], set[str]]

PROVIDER_CLIS = frozenset(
    {"gcloud", "gsutil", "bq", "aws", "eksctl", "az", "azd", "terraform", "tofu", "pulumi", "lightsail"}
)
CREDENTIAL_VARS = re.compile(
    r"\b(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|AWS_PROFILE|AWS_WEB_IDENTITY_TOKEN_FILE"
    r"|GOOGLE_APPLICATION_CREDENTIALS|GOOGLE_CLOUD_PROJECT|CLOUDSDK_[A-Z_]+|AZURE_[A-Z_]+"
    r"|MCP_RE_GCP_ACCESS_TOKEN|MCP_RE_AWS_KMS_ROLE_ARN|MCP_RE_GCP_KMS_GSA|ECR_REGISTRY)\b"
)
REGISTRY_HOSTS = re.compile(r"\.dkr\.ecr\.|docker\.pkg\.dev|(?<![\w.-])gcr\.io|azurecr\.io|amazonaws\.com")
CLOUD_SDK_MODULES = ("boto3", "botocore", "google.cloud", "google.auth", "azure")

#: Files that must be in the closure, and the ones that must not.
REQUIRED_MEMBERS = (
    "docs/security/fleet-proofs-kind.sh",
    "docs/security/fleet-proofs-core.sh",
    "tools/slo/rehearse_job_spec.sh",
    "tools/slo/run_slo_job.sh",
)
FORBIDDEN_MEMBERS = ("docs/security/gke-multi-replica-validation.sh", "tools/slo/run_slo_job_cloud.sh")

#: Directories a closure Python file's bare `import x` may resolve into.
PY_IMPORT_DIRS = ("scripts", "scripts/lib", "tools/slo", "tools/verification", "docs/security")

REPO_PATH = re.compile(r"(?<![\w.-])((?:scripts|tools|docs)/[A-Za-z0-9_./-]*[A-Za-z0-9_-])")
#: The repository's inline-comment idiom inside a `&&` chain: `` `# …` ``.
BACKTICK_COMMENT = re.compile(r"`#[^`]*`")
MESSAGE_WORDS = {"echo", "printf", "log", "fail", "verdict", "warn", "die"}
PREFIX_WORDS = {
    "exec", "command", "env", "sudo", "time", "nohup", "xargs", "!", "if", "then", "else", "elif",
    "do", "while", "until", "builtin", "eval", "bash", "sh", "-c", "-e", "-x", "-lc",
}
PROBE_WORDS = {"which", "type", "hash"}
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

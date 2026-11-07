# SPDX-License-Identifier: Apache-2.0
"""The selftest's fixtures: a small provider-neutral tree, and the injections the gate must refuse."""

from __future__ import annotations

from _provider_neutral.config import ENTRY

#: A closure that is clean: the kind driver and proof core are reached, the cloud driver is not.
BASE_TREE = {
    ENTRY: "#!/bin/bash\nrun stage_kind\nstage_kind() {\n  docs/security/fleet-proofs-kind.sh || return $?\n"
           "  tools/slo/rehearse_job_spec.sh\n}\n",
    "docs/security/fleet-proofs-kind.sh": "#!/bin/bash\n"
        "printf 'cloud custody belongs to docs/security/gke-multi-replica-validation.sh\\n' >&2\n"
        "exec \"$REPO_ROOT/docs/security/fleet-proofs-core.sh\"\n",
    "docs/security/fleet-proofs-core.sh": "#!/bin/bash\n# gcloud is never called here\n"
        "echo 'run gcloud yourself'\nLOADGEN=\"$(kubectl get pod -o json | python3 \"$REPO_ROOT/docs/security/sel.py\")\"\n",
    "docs/security/sel.py": "import json\nTABLE = {'gcloud': 'a provider, as data'}\n",
    "tools/slo/rehearse_job_spec.sh": "#!/bin/bash\ntools/slo/run_slo_job.sh - kind-local 1 out.json\n",
    "tools/slo/run_slo_job.sh": "#!/bin/bash\nkubectl apply -f -\n",
    "docs/security/gke-multi-replica-validation.sh": "#!/bin/bash\ngcloud container clusters create x\n",
}

CORE = "docs/security/fleet-proofs-core.sh"

#: (text appended to the provider-neutral core, the phrase the refusal must contain)
CORE_REFUSALS = (
    # THE REGRESSION: the exact line the rehearsal hit, in the provider-neutral core.
    ('PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || true)}"\n', "gcloud"),
    # A guard does not exempt a provider call from the closure.
    ('if [[ "$PROVIDER" == eks ]]; then aws sts get-caller-identity; fi\n', "aws"),
    ("x=`eksctl get clusters`\n", "eksctl"),
    ("command -v gcloud >/dev/null && echo yes\n", "probed"),
    ("timeout 30 az account show\n", "az"),
    ("python3 - <<'PY'\nimport subprocess; subprocess.run(['aws', 'sts'])\nPY\n", "quoted literal"),
    ('export K="$AWS_ACCESS_KEY_ID"\n', "credential"),
    ('IMG="123.dkr.ecr.eu-north-1.amazonaws.com/x:1"\n', "registry"),
)

#: (the Python a closure file holds, the phrase the refusal must contain)
PYTHON_REFUSALS = (
    ("import subprocess\nsubprocess.run(['gcloud', 'auth', 'print-access-token'])\n", "process"),
    ("import shutil\nshutil.which('aws')\n", "process"),
    ("import boto3\n", "cloud SDK"),
    ("import os\nos.environ['GOOGLE_APPLICATION_CREDENTIALS']\n", "credential read"),
    ("import os\nos.environ.get('AWS_PROFILE')\n", "credential read"),
)

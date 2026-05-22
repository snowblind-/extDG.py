#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
bigip_upload_datagroup.py  --  Python 2.7

Upload a flat file to a BIG-IP via iControl REST and associate (create or
update) an external data-group that references it.

The correct 3-step sequence is:
  1. POST /mgmt/shared/file-transfer/uploads/<name>   -- stage the file
  2. POST /mgmt/tm/sys/file/data-group                -- register/move to /var/class/
  3. POST /mgmt/tm/ltm/data-group/external            -- create the DG object

Usage
-----
python bigip_upload_datagroup.py \
    --host 192.0.2.1 \
    --user admin \
    --password secret \
    --file /path/to/mylist.txt \
    --datagroup ext_dg_name \
    [--type string|integer|ip] \
    [--partition Common] \
    [--no-verify]

Notes
-----
* --type controls the sys/file/data-group registration (string/integer/ip).
  The ltm/data-group/external object does NOT accept 'type' when
  externalFileName is present (apiError 26214401); TMOS infers it.
* The file-object name is set to the same value as --datagroup for simplicity.
* Tested against TMOS 13.x - 17.x.
"""

from __future__ import print_function

import argparse
import base64
import getpass
import json
import math
import os
import ssl
import sys
import httplib

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CHUNK_SIZE   = 524288   # 512 KiB – BIG-IP hard limit per upload chunk
UPLOAD_URI   = "/mgmt/shared/file-transfer/uploads"
DGFILE_URI   = "/mgmt/tm/sys/file/data-group"
DG_URI       = "/mgmt/tm/ltm/data-group/external"


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------
class BigIPClient(object):
    """Minimal iControl REST client for Python 2.7 (stdlib only)."""

    def __init__(self, host, user, password, verify_ssl=True):
        self.host     = host
        self.user     = user
        self.password = password
        self.verify   = verify_ssl
        self._token   = None

    def _connection(self):
        if self.verify:
            return httplib.HTTPSConnection(self.host, 443)
        ctx = ssl._create_unverified_context()
        return httplib.HTTPSConnection(self.host, 443, context=ctx)

    def _auth_headers(self):
        if self._token:
            return {"X-F5-Auth-Token": self._token}
        creds = base64.b64encode(
            "{0}:{1}".format(self.user, self.password).encode("utf-8")
        ).decode("ascii")
        return {"Authorization": "Basic {0}".format(creds)}

    def _request(self, method, uri, body=None, extra_headers=None):
        conn    = self._connection()
        headers = self._auth_headers()
        if extra_headers:
            headers.update(extra_headers)
        conn.request(method, uri, body=body, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.read()

    def get(self, uri):
        return self._request("GET", uri)

    def post(self, uri, payload, content_type="application/json"):
        return self._request("POST", uri, payload,
                             {"Content-Type": content_type})

    def put(self, uri, payload, content_type="application/json"):
        return self._request("PUT", uri, payload,
                             {"Content-Type": content_type})

    def patch(self, uri, payload, content_type="application/json"):
        return self._request("PATCH", uri, payload,
                             {"Content-Type": content_type})

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------
    def login(self):
        payload = json.dumps({
            "username"          : self.user,
            "password"          : self.password,
            "loginProviderName" : "tmos",
        })
        conn = self._connection()
        conn.request("POST", "/mgmt/shared/authn/login", body=payload,
                     headers={"Content-Type": "application/json"})
        resp   = conn.getresponse()
        status = resp.status
        body   = resp.read()
        if status != 200:
            raise RuntimeError(
                "Login failed (HTTP {0}): {1}".format(status, body))
        self._token = json.loads(body)["token"]["token"]
        print("[*] Authenticated – token acquired.")

    # ------------------------------------------------------------------
    # Chunked upload  →  /var/config/rest/downloads/<name>
    # ------------------------------------------------------------------
    def upload_file(self, local_path, remote_filename=None):
        if remote_filename is None:
            remote_filename = os.path.basename(local_path)

        file_size    = os.path.getsize(local_path)
        if file_size == 0:
            raise ValueError("Upload file is empty: {0}".format(local_path))

        upload_uri   = "{0}/{1}".format(UPLOAD_URI, remote_filename)
        staging_path = "/var/config/rest/downloads/{0}".format(remote_filename)
        total_chunks = int(math.ceil(file_size / float(CHUNK_SIZE)))

        print("[*] Uploading '{0}' ({1} bytes, {2} chunk(s)) ...".format(
            local_path, file_size, total_chunks))

        with open(local_path, "rb") as fh:
            for chunk_index in range(total_chunks):
                chunk = fh.read(CHUNK_SIZE)
                start = chunk_index * CHUNK_SIZE
                end   = start + len(chunk) - 1

                conn    = self._connection()
                headers = self._auth_headers()
                headers.update({
                    "Content-Type" : "application/octet-stream",
                    "Content-Range": "{0}-{1}/{2}".format(start, end, file_size),
                })
                conn.request("POST", upload_uri, body=chunk, headers=headers)
                resp   = conn.getresponse()
                status = resp.status
                rbody  = resp.read()

                if status not in (200, 201):
                    raise RuntimeError(
                        "Chunk {0} upload failed (HTTP {1}): {2}".format(
                            chunk_index, status, rbody))

                pct = int((chunk_index + 1) / float(total_chunks) * 100)
                sys.stdout.write("\r    Progress: {0}%".format(pct))
                sys.stdout.flush()

        print("\n[*] Upload complete – staging path: {0}".format(staging_path))
        return staging_path


# ---------------------------------------------------------------------------
# Step 2: register file object  →  /mgmt/tm/sys/file/data-group
#
# This is what actually copies the file from the REST downloads staging area
# into /var/class/<partition>/ and makes TMOS aware of it.
# The externalFileName in the ltm object must match this iControl name.
# ---------------------------------------------------------------------------
def full_path(partition, name):
    return "/{0}/{1}".format(partition, name)


def dgfile_exists(client, partition, name):
    uri    = "{0}/~{1}~{2}".format(DGFILE_URI, partition, name)
    status, _ = client.get(uri)
    return status == 200


def register_file_object(client, partition, name, dg_type, staging_path):
    """
    Create or update a sys/file/data-group entry.

    sourcePath must use the  file:<absolute-path>  URI scheme so that TMOS
    reads from the staging area and copies the content into /var/class/.
    """
    source_path = "file:{0}".format(staging_path)

    if dgfile_exists(client, partition, name):
        # Update existing file object – PUT replaces it
        uri     = "{0}/~{1}~{2}".format(DGFILE_URI, partition, name)
        payload = json.dumps({
            "sourcePath": source_path,
            "type"      : dg_type,
        })
        status, body = client.put(uri, payload)
        verb = "updated"
    else:
        payload = json.dumps({
            "name"      : name,
            "partition" : partition,
            "sourcePath": source_path,
            "type"      : dg_type,
        })
        status, body = client.post(DGFILE_URI, payload)
        verb = "created"

    if status not in (200, 201):
        raise RuntimeError(
            "Failed to {0} sys/file/data-group (HTTP {1}): {2}".format(
                verb, status, body))

    print("[*] sys/file/data-group '{0}' {1}.".format(
        full_path(partition, name), verb))
    return json.loads(body)


# ---------------------------------------------------------------------------
# Step 3: create/update  →  /mgmt/tm/ltm/data-group/external
#
# externalFileName must be the iControl full-path of the sys/file/data-group
# object, NOT a raw filesystem path.
#
# BIG-IP rejects 'type' here when externalFileName is present (apiError
# 26214401); the type is inherited from the file object.
# ---------------------------------------------------------------------------
def dg_exists(client, partition, name):
    uri    = "{0}/~{1}~{2}".format(DG_URI, partition, name)
    status, _ = client.get(uri)
    return status == 200


def create_external_dg(client, partition, name):
    payload = json.dumps({
        "name"            : name,
        "partition"       : partition,
        "externalFileName": full_path(partition, name),
    })
    status, body = client.post(DG_URI, payload)
    if status not in (200, 201):
        raise RuntimeError(
            "Failed to create ltm/data-group/external (HTTP {0}): {1}".format(
                status, body))
    print("[*] ltm/data-group/external '{0}' created.".format(
        full_path(partition, name)))
    return json.loads(body)


def update_external_dg(client, partition, name):
    uri     = "{0}/~{1}~{2}".format(DG_URI, partition, name)
    # Re-point at the same file object to force TMOS to reload the content.
    payload = json.dumps({
        "externalFileName": full_path(partition, name),
    })
    status, body = client.patch(uri, payload)
    if status not in (200, 201):
        raise RuntimeError(
            "Failed to update ltm/data-group/external (HTTP {0}): {1}".format(
                status, body))
    print("[*] ltm/data-group/external '{0}' updated.".format(
        full_path(partition, name)))
    return json.loads(body)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Upload a file to BIG-IP and associate it with an external "
            "data-group via iControl REST."
        )
    )
    parser.add_argument("--host",      required=True,
                        help="BIG-IP management IP or hostname")
    parser.add_argument("--user",      required=True,
                        help="iControl REST username")
    parser.add_argument("--password",  default=None,
                        help="iControl REST password")
    parser.add_argument("--prompt-password", action="store_true",
                        help="Prompt for password interactively")
    parser.add_argument("--file",      required=True,
                        help="Local file to upload")
    parser.add_argument("--datagroup", required=True,
                        help="Name for the data-group (and file object)")
    parser.add_argument("--type",      default="string",
                        choices=["string", "integer", "ip"],
                        help="Data-group type (default: string)")
    parser.add_argument("--partition", default="Common",
                        help="BIG-IP partition (default: Common)")
    parser.add_argument("--no-verify", action="store_true",
                        help="Disable SSL certificate verification")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.prompt_password or args.password is None:
        password = getpass.getpass(
            "Password for {0}@{1}: ".format(args.user, args.host))
    else:
        password = args.password

    if not os.path.isfile(args.file):
        print("[!] File not found: {0}".format(args.file), file=sys.stderr)
        sys.exit(1)

    client = BigIPClient(args.host, args.user, password,
                         verify_ssl=not args.no_verify)

    # 1. Authenticate
    client.login()

    # 2. Upload to staging area
    remote_filename = os.path.basename(args.file)
    staging_path    = client.upload_file(args.file, remote_filename)

    # 3. Register / update the sys/file/data-group object
    #    (copies file from staging into /var/class/ and makes TMOS aware)
    register_file_object(client, args.partition, args.datagroup,
                         args.type, staging_path)

    # 4. Create or update the ltm/data-group/external object
    if dg_exists(client, args.partition, args.datagroup):
        print("[*] Data-group already exists – updating.")
        update_external_dg(client, args.partition, args.datagroup)
    else:
        print("[*] Data-group does not exist – creating.")
        create_external_dg(client, args.partition, args.datagroup)

    print("[+] Done.")


if __name__ == "__main__":
    main()

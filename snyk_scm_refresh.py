#!/usr/bin/env python3
"""
Keep Snyk projects in sync with their corresponding SCM repositories
"""
import logging
import sys
from os import getenv
import common
from app import run

if __name__ == "__main__":

    if common.ARGS.audit_large_repos:
        print("\n****** AUDIT LARGE REPOS MODE ******\n")
        print(f"check {common.LARGE_REPOS_AUDIT_RESULTS_FILE.name} after script completes\n")
    elif common.ARGS.dry_run:
        print("\n****** DRY-RUN MODE ******\n")
    for arg in vars(common.ARGS):
        if any(arg in x for x in ['sca', 'container', 'iac', 'code']):
            print(f"{arg}={common.toggle_to_bool(getattr(common.ARGS, arg))}")
        else:
            print(f"{arg}={getattr(common.ARGS, arg)}")
    print("---")

    if getenv("SNYK_TOKEN") is None:
        print("token not set at $SNYK_TOKEN")
        sys.exit(1)

    if common.GITHUB_TOKEN is None and common.GITHUB_ENTERPRISE_TOKEN is None:
        print("1 of $GITHUB_TOKEN (GitHub.com) or $GITHUB_ENTERPRISE_TOKEN (GitHub Enteprise) "
        "must be set")
        print("If using $GITHUB_ENTERPRISE_TOKEN, you must also set $GITHUB_ENTERPRISE_HOST")
        sys.exit(1)

    if common.GITHUB_ENTERPRISE_HOST is not None and common.GITHUB_ENTERPRISE_TOKEN is None:
        print("$GITHUB_ENTERPRISE_TOKEN must be set when using $GITHUB_ENTERPRISE_HOST")
        sys.exit(1)

    if common.GITHUB_ENTERPRISE_TOKEN is not None and common.GITHUB_ENTERPRISE_HOST is None:
        print("$GITHUB_ENTERPRISE_HOST must be set when using $GITHUB_ENTERPRISE_TOKEN")
        sys.exit(1)

    if common.GITHUB_ENTERPRISE_TOKEN is not None and common.GITHUB_ENTERPRISE_HOST is not None:
        GITHUB_ENTERPRISE_TOKEN_HIDDEN = \
            f"****{common.GITHUB_ENTERPRISE_TOKEN[len(common.GITHUB_ENTERPRISE_TOKEN)-4:]}"
        sys.stdout.write("Using GHE: ")
        print(f"{GITHUB_ENTERPRISE_TOKEN_HIDDEN}@{common.GITHUB_ENTERPRISE_HOST}")

    if common.GITHUB_TOKEN is not None:
        GITHUB_TOKEN_HIDDEN = f"****{common.GITHUB_TOKEN[len(common.GITHUB_TOKEN)-4:]}"
        sys.stdout.write("Using GH: ")
        print(f"{GITHUB_TOKEN_HIDDEN}")

    print("---")
    if common.ARGS.debug:
        logging.basicConfig(filename=common.LOG_FILENAME, level=logging.DEBUG, filemode="w")
    else:
        logging.basicConfig(filename=common.LOG_FILENAME, level=logging.INFO, filemode="w")

    run()

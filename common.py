from os import getenv
from snyk import SnykClient
from app.utils.github_utils import (
    create_github_client,
    create_github_enterprise_client
)
import argparse

MANIFEST_REGEX_PATTERN = '^(?![.]).*(package[.]json$|Gemfile[.]lock$|pom[.]xml$|build[.]gradle$|.*[.]lockfile$|build[.]sbt$|.*req.*[.]txt$|Gopkg[.]lock|go[.]mod|vendor[.]json|packages[.]config|.*[.]csproj|.*[.]fsproj|.*[.]vbproj|project[.]json|project[.]assets[.]json|composer[.]lock|Podfile|Podfile[.]lock|.*[.]yaml|.*[.]yml|Dockerfile)'

GITHUB_ENABLED = False
GITHUB_ENTERPRISE_ENABLED = False

SNYK_TOKEN = getenv("SNYK_TOKEN")
GITHUB_TOKEN = getenv("GITHUB_TOKEN")
GITHUB_ENTERPRISE_TOKEN = getenv("GITHUB_ENTERPRISE_TOKEN")
GITHUB_ENTERPRISE_HOST = getenv("GITHUB_ENTERPRISE_HOST")

LOG_PREFIX = "snyk-scm-refresh"
LOG_FILENAME = LOG_PREFIX + ".log"
POTENTIAL_DELETES_FILE = open("%s_potential-repo-deletes.csv" % LOG_PREFIX, "w")
POTENTIAL_DELETES_FILE.write("org,repo\n")
STALE_MANIFESTS_DELETED_FILE = open(
    "%s_stale-manifests-deleted.csv" % LOG_PREFIX, "w"
)
STALE_MANIFESTS_DELETED_FILE.write("org,project\n")
RENAMED_MANIFESTS_DELETED_FILE = open(
    "%s_renamed-manifests-deleted.csv" % LOG_PREFIX, "w"
)
RENAMED_MANIFESTS_DELETED_FILE.write("org,project\n")
RENAMED_MANIFESTS_PENDING_FILE = open(
    "%s_renamed-manifests-pending.csv" % LOG_PREFIX, "w"
)
RENAMED_MANIFESTS_PENDING_FILE.write("org,project\n")
COMPLETED_PROJECT_IMPORTS_FILE = open(
    "%s_completed-project-imports.csv" % LOG_PREFIX, "w"
)
COMPLETED_PROJECT_IMPORTS_FILE.write("org,project,success\n")
REPOS_SKIPPED_ON_ERROR_FILE = open(
    "%s_repos-skipped-on-error.csv" % LOG_PREFIX, "w"
)
REPOS_SKIPPED_ON_ERROR_FILE.write("org,repo,status\n")
UPDATED_PROJECT_BRANCHES_FILE = open(
    "%s_updated-project-branches.csv" % LOG_PREFIX, "w"
)
UPDATED_PROJECT_BRANCHES_FILE.write("org,project_name,project_id,new_branch\n")
UPDATE_PROJECT_BRANCHES_ERRORS_FILE = open(
    "%s_update-project-branches-errors.csv" % LOG_PREFIX, "w"
)
UPDATE_PROJECT_BRANCHES_ERRORS_FILE.write("org,project_name,project_id,new_branch\n")

PENDING_REMOVAL_MAX_CHECKS = 45
PENDING_REMOVAL_CHECK_INTERVAL = 20

snyk_client = SnykClient(SNYK_TOKEN)

if (GITHUB_TOKEN):
    GITHUB_ENABLED = True
    gh_client = create_github_client(GITHUB_TOKEN)

if (GITHUB_ENTERPRISE_HOST):
    GITHUB_ENTERPRISE_ENABLED = True
    gh_enterprise_client = create_github_enterprise_client(GITHUB_ENTERPRISE_TOKEN, GITHUB_ENTERPRISE_HOST)

def parse_command_line_args():
    """Parse command-line arguments"""

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--org-id",
        type=str,
        help="The Snyk Organisation Id found in Organization > Settings. \
            If omitted, process all orgs the Snyk user has access to.",
        required=False,
    )
    parser.add_argument(
        "--repo-name",
        type=str,
        help="The full name of the repo to process (e.g. githubuser/githubrepo). \
            If omitted, process all repos in the Snyk org.",
        required=False,
    )
    parser.add_argument(
        "--dry-run",
        help="Simulate processing of the script without making changes to Snyk",
        required=False,
        action="store_true",
    )

    return parser.parse_args()

ARGS = parse_command_line_args()
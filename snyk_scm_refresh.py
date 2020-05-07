#!/usr/local/bin/python3
"""
Keep Snyk projects in sync with their corresponding SCM repositories
"""
import argparse
import logging
import sys
import time
from os import environ, getenv
import github
from snyk import SnykClient

from app.utils.github_utils import (
    create_github_client,
    get_gh_repo_status,
)


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
        "--project-id",
        type=str,
        help="The Snyk Project Id found in Project > Settings. if omitted, process all projects.",
        required=False,
    )
    parser.add_argument(
        "--dry-run",
        help="Simulate processing of the script without making changes to Snyk",
        required=False,
        action="store_true",
    )

    return parser.parse_args()


def delete_snyk_project(project_id, org_id):
    """Delete a single Snyk project"""
    snyk_client.organizations.get(org_id).projects.get(project_id).delete()


def delete_stale_manifests(snyk_repo_projects):
    """Delete Snyk projects for which the corresponding manifest no longer exists"""

    gh_client = create_github_client()

    try:
        gh_repo = gh_client.get_repo(snyk_repo_projects[0]["repo_full_name"])
    except:
        gh_repo = gh_client.get_user().get_repo(snyk_repo_projects[0]["repo_name"])

    for snyk_repo_project in snyk_repo_projects:
        try:
            gh_repo.get_contents(snyk_repo_project["manifest"])
        except github.UnknownObjectException:
            sys.stdout.write(
                "  - [%s] manifest %s no longer exists, deleting from Snyk..."
                % (snyk_repo_project["repo_full_name"], snyk_repo_project["manifest"])
            )
            sys.stdout.flush()
            delete_snyk_project(snyk_repo_project["id"], snyk_repo_project["org_id"])
            STALE_MANIFESTS_DELETED_FILE.write(
                "%s,%s,%s\n"
                % (
                    snyk_repo_project["name"],
                    snyk_repo_project["id"],
                    snyk_repo_project["org_id"],
                )
            )
            print("Done")
            if not dry_run:
                time.sleep(2)


def delete_renamed_repo_manifests(snyk_repo_projects):
    """Delete Snyk projects (manifests) that exist under their old repo name"""
    for snyk_repo_project in snyk_repo_projects:
        delete_snyk_project(snyk_repo_project["id"], snyk_repo_project["org_id"])
        RENAMED_MANIFESTS_DELETED_FILE.write(
            "%s,%s,%s\n"
            % (
                snyk_repo_project["name"],
                snyk_repo_project["id"],
                snyk_repo_project["org_id"],
            )
        )
        if not dry_run:
            time.sleep(2)


def import_github_repo(org_id, owner, name):
    """Import a Github Repo into Snyk"""

    org = snyk_client.organizations.get(org_id)
    org.import_project("github.com/%s/%s" % (owner, name))


def build_snyk_project_list(snyk_orgs):
    """Build list of Snyk projects across all Snyk orgs in scope"""
    snyk_gh_projects = []
    snyk_projects = []

    for snyk_org in snyk_orgs:
        gh_integration_id = snyk_org.integrations.filter(name="github")[0].id
        if project_id_filter:
            snyk_projects.append(snyk_org.projects.get(project_id_filter))
        else:
            snyk_projects = snyk_org.projects.all()
        for project in snyk_projects:
            if project.origin == "github":
                # snyk/goof(master):pom.xml or just snyk/goof:pom.xml
                split_project_name = project.name.split(
                    ":"
                )  # snyk/goof(master) or #snyk/goof
                tmp_branch_split = split_project_name[0].split("(")
                if len(tmp_branch_split) == 2:
                    branch_from_name = tmp_branch_split[1].split(")")[0]
                else:
                    branch_from_name = ""
                split_repo_name = tmp_branch_split[0].split("/")
                snyk_gh_projects.append(
                    {
                        "id": project.id,
                        "name": project.name,
                        "repo_full_name": split_project_name[0].split("(")[0],
                        "repo_owner": split_repo_name[0],
                        "repo_name": split_repo_name[1].split("(")[0],
                        "manifest": split_project_name[1],
                        "org_id": snyk_org.id,
                        "snyk_github_check_name": f"license/snyk - {split_project_name[1]} ({snyk_org.name})",
                        "gh_integration_id": gh_integration_id,
                        "branch_from_name": branch_from_name,
                    }
                )
    return snyk_gh_projects


def build_unique_repos(snyk_gh_projects):
    """Build list of unique repositories from a given list of Snyk projects"""
    snyk_gh_repos = []
    for project in snyk_gh_projects:
        if project["repo_full_name"] not in {s["full_name"] for s in snyk_gh_repos}:
            snyk_gh_repos.append(
                {
                    "full_name": project["repo_full_name"],
                    "owner": project["repo_owner"],
                    "name": project["repo_name"],
                    "org_id": project["org_id"],
                    "gh_integration_id": project["gh_integration_id"],
                    "branch_from_name": project["branch_from_name"],
                }
            )
    return snyk_gh_repos


def main():
    """Main"""

    print("dry-run = %s" % dry_run)
    sys.stdout.write("Retrieving Snyk Projects...")
    sys.stdout.flush()

    snyk_orgs = []

    # if --orgId exists, use it
    # otherwise get all orgs the api user is part of
    if org_id_filter:
        snyk_orgs.append(snyk_client.organizations.get(org_id_filter))
    else:
        snyk_orgs = snyk_client.organizations.all()

    # build complete Snyk project list
    snyk_gh_projects = build_snyk_project_list(snyk_orgs)
    sys.stdout.write("%d" % len(snyk_gh_projects))

    # build unique repos in Snyk from project list
    snyk_gh_repos = build_unique_repos(snyk_gh_projects)
    sys.stdout.write(" [%d Unique repos]\n" % len(snyk_gh_repos))

    # clean up snyk projects
    for snyk_gh_repo in snyk_gh_repos:
        gh_repo_status = get_gh_repo_status(snyk_gh_repo, github_token)
        # print(gh_repo_status)
        sys.stdout.write(
            "Snyk name: %s | Github Status: %s [%s]\n"
            % (
                snyk_gh_repo["full_name"],
                gh_repo_status["response_code"],
                gh_repo_status["response_message"],
            )
        )
        sys.stdout.flush()

        # project not renamed/moved
        if gh_repo_status["response_code"] == 200:
            # remove any manifests that no longer exist at the github repo before re-importing
            snyk_repo_projects = list(
                filter(
                    lambda x: x["repo_full_name"] == snyk_gh_repo["full_name"],
                    snyk_gh_projects,
                )
            )
            print(
                "  - [%s] Checking (%d) for stale manifests"
                % (gh_repo_status["gh_name"], len(snyk_repo_projects))
            )
            if not dry_run:
                delete_stale_manifests(snyk_repo_projects)
            # then, import with existing name to catch any new manifests
            print(
                "  - [%s] Adding any new manifests via Import"
                % gh_repo_status["gh_name"]
            )
            if not dry_run:
                import_github_repo(
                    snyk_gh_repo["org_id"], snyk_gh_repo["owner"], snyk_gh_repo["name"]
                )

        # project no longer exists
        elif gh_repo_status["response_code"] == 404:
            # potential deletes, output to file for review
            print("  - [%s] Logging potential delete" % snyk_gh_repo["full_name"])
            POTENTIAL_DELETES_FILE.write("%s\n" % (snyk_gh_repo["full_name"]))

        # project has moved/been renamed
        elif gh_repo_status["response_code"] == 301:
            # import with new name to catch any new manifests and fix broken PR status checks
            print("  - [%s] Snyk import job submitted" % gh_repo_status["gh_name"])
            if not dry_run:
                import_github_repo(
                    gh_repo_status["snyk_org_id"],
                    gh_repo_status["gh_owner"],
                    gh_repo_status["gh_name"],
                )
            snyk_repo_projects = list(
                filter(
                    lambda x: x["repo_full_name"] == snyk_gh_repo["full_name"],
                    snyk_gh_projects,
                )
            )
            print(
                "  - [%s] Removing projects under old name" % snyk_gh_repo["full_name"]
            )
            if not dry_run:
                delete_renamed_repo_manifests(snyk_repo_projects)

        if not dry_run:
            time.sleep(10)

    # check and log status of submitted import jobs


if __name__ == "__main__":
    LOG_PREFIX = "snyk-scm-refresh"

    if environ.get("SNYK_TOKEN", "False") == "False":
        print("token not set at $SNYK_TOKEN")
        sys.exit(1)

    if environ.get("GITHUB_TOKEN", "False") == "False":
        print("github-token not set at $GITHUB_TOKEN")
        sys.exit(1)

    LOG_FILENAME = LOG_PREFIX + ".log"
    logging.basicConfig(filename=LOG_FILENAME, level=logging.DEBUG, filemode="w")

    snyk_token = getenv("SNYK_TOKEN")
    github_token = getenv("GITHUB_TOKEN")
    args = parse_command_line_args()
    org_id_filter = args.org_id
    project_id_filter = args.project_id
    dry_run = args.dry_run

    snyk_client = SnykClient(snyk_token)

    SUMMARY_FILE = open("%s_summary.csv" % LOG_PREFIX, "w")
    POTENTIAL_DELETES_FILE = open("%s_potential-deletes.csv" % LOG_PREFIX, "w")
    STALE_MANIFESTS_DELETED_FILE = open(
        "%s_stale-manifests-deleted.csv" % LOG_PREFIX, "w"
    )
    RENAMED_MANIFESTS_DELETED_FILE = open(
        "%s_renamed-manifests-deleted.csv" % LOG_PREFIX, "w"
    )

    main()
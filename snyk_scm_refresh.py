#!/usr/local/bin/python3
"""
Keep Snyk projects in sync with their corresponding SCM repositories
"""
import argparse
import logging
import sys
import time
import re
from os import environ, getenv
import github
import snyk.errors
from snyk import SnykClient

from app.utils.github_utils import (
    create_github_client,
    get_gh_repo_status,
)

from app.utils.snyk_helper import (
    unique_import_jobs_from_status_checks,
    unique_repos_from_snyk_projects,
    get_snyk_projects_from_github_repo
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

    org = snyk_client.organizations.get(org_id)

    try:
        project = org.projects.get(project_id)
        return project.delete()
    except snyk.errors.SnykNotFoundError:
        print("    - Project %s not found in org %s ..." % (project_id, org_id))
        return False

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
                "%s,%s\n"
                % (
                    snyk_repo_project["org_name"],
                    snyk_repo_project["name"]
                )
            )
            print("Done")
            if not dry_run:
                time.sleep(2)

def process_import_status_checks(import_status_checks, deletes_pending_on_import):
    """
    Check status of pending import jobs
    up to PENDING_REMOVAL_MAX_CHECKS times,
    waiting PENDING_REMOVAL_CHECK_INTERVAL seconds between checks
    """
    check_count = 0
    import_status_processed = []

    print("Checking import statuses, polling for up to %s minutes..."
          % str((PENDING_REMOVAL_MAX_CHECKS * PENDING_REMOVAL_CHECK_INTERVAL)/60))

    while check_count < PENDING_REMOVAL_MAX_CHECKS:
        # get unique jobs from import results
        unique_import_jobs = unique_import_jobs_from_status_checks(import_status_checks)

        # check each import job statuses
        for import_job in unique_import_jobs:
            import_status = get_import_status(
                import_job["import_status_url"], import_job["org_id"]
            )
            # process each individual repo import
            for import_status_log in import_status["logs"]:
                if import_status_log["name"] not in import_status_processed:
                    print("  - [%s] Import status: %s" % (
                        import_status_log["name"], import_status_log["status"]
                    ))
                    # if repo import status is complete, log
                    # and delete any pending waiting on this repo import
                    if import_status_log["status"] == "complete":
                        for project in import_status_log["projects"]:
                            COMPLETED_PROJECT_IMPORTS_FILE.write("%s,%s:%s,%s\n" % (
                                import_job["org_id"],
                                import_status_log["name"],
                                project["targetFile"],
                                project["success"]
                            ))

                        if len(deletes_pending_on_import) > 0:
                            for pending_delete in deletes_pending_on_import[0]:
                                if pending_delete["new_repo"] == import_status_log["name"]:
                                    print("delete pending projects here %s:%s:%s" % (
                                        pending_delete["pending_org_id"],
                                        pending_delete["old_repo"],
                                        pending_delete["pending_manifest"]
                                    ))

                                    delete_snyk_project(
                                        pending_delete["pending_project_id"],
                                        pending_delete["pending_org_id"]
                                    )

                                    RENAMED_MANIFESTS_DELETED_FILE.write("%s,%s:%s\n" % (
                                        pending_delete["pending_org_id"],
                                        pending_delete["old_repo"],
                                        pending_delete["pending_manifest"]
                                    ))
                        # track which repo import jobs have been processed
                        import_status_processed.append(import_status_log["name"])

        if len(import_status_checks) == len(import_status_processed):
            print("None Pending, Done.\n")
            return
        else:
            sys.stdout.write("%s now pending" % (
                len(import_status_checks) - len(import_status_processed)
            ))
            sys.stdout.flush()

        check_count += 1
        if check_count == PENDING_REMOVAL_MAX_CHECKS:
            print(
                "\nExiting with %d pending removals, logging...\n" % (
                    len(import_status_checks) - len(import_status_processed)
                )
            )
            for import_status_check in import_status_checks:
                if import_status_check["owner"] + '/' + import_status_check["name"] \
                    not in import_status_processed:
                    RENAMED_MANIFESTS_PENDING_FILE.write(
                        "%s,%s/%s\n" % (
                            import_status_check["org_name"],
                            import_status_check["owner"],
                            import_status_check["name"]
                        )
                    )
            return
        else:
            print(", Checking back in %d seconds..." % PENDING_REMOVAL_CHECK_INTERVAL)
        time.sleep(PENDING_REMOVAL_CHECK_INTERVAL)

def get_import_status(import_status_url, org_id):
    """Retrieve status data for a Snyk import job"""

    # extract path segment for later use
    path = re.search('.+(org/.+)', import_status_url).group(1)

    org = snyk_client.organizations.get(org_id)
    response = org.client.get(path)
    return response.json()

def import_github_repo(org_id, owner, name):
    """Import a Github Repo into Snyk"""

    org = snyk_client.organizations.get(org_id)
    integration_id = org.integrations.filter(name="github")[0].id

    path = "org/%s/integrations/%s/import" % (org.id, integration_id)
    payload = {
        "target": {"owner": owner, "name": name, "branch": ""}
    }
    try:
        response = org.client.post(path, payload)
    except snyk.errors.SnykHTTPError as err:
        if err.code in [502,504]:
            print("Server error, lets try again in a minute...")
            time.sleep(60)
            response = org.client.post(path, payload)

    return {
        "org_id": org.id,
        "org_name": org.name,
        "owner": owner,
        "name": name,
        "job_id": re.search('org/.+/integrations/.+/import/(.+)', \
            response.headers['Location']).group(1),
        "import_status_url": response.headers['Location']
    }

def build_snyk_project_list(snyk_orgs):
    """Build list of Snyk projects across all Snyk orgs in scope"""
    snyk_gh_projects = []
    snyk_projects = []

    for snyk_org in snyk_orgs:
        try:
            gh_integration_id = snyk_org.integrations.filter(name="github")[0].id
        except snyk.errors.SnykHTTPError:
            print(
                "\n\nUnable to retrieve GitHub integration id for org: %s, check permissions\n\n"
                % snyk_org.name
            )
            sys.exit(1)
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
                        "org_name": snyk_org.name,
                        "gh_integration_id": gh_integration_id,
                        "branch_from_name": branch_from_name,
                    }
                )
    return snyk_gh_projects

def log_potential_delete(org_name, repo_name):
    """ Log potential repo deletion """
    print("  - [%s] Logging potential delete" % repo_name)
    POTENTIAL_DELETES_FILE.write("%s,%s\n" % (org_name, repo_name))

def process_snyk_repo_projects_and_get_check_data(snyk_repo_projects, snyk_gh_repo):
    """
    Check if existing manifests still exist
    Re-import existing repos to pick up any files
    Detect repos that no longer exist
    if a repo has been renamed, bring in the new one and delete the old
    """

    _import_response = []
    _deletes_pending_on_import = []

    try:
        gh_repo_status = get_gh_repo_status(snyk_gh_repo, github_token)
    except RuntimeError as err:
        raise RuntimeError("Failed to query GitHub repository!") from err

    print("Snyk Org: %s | Snyk name: %s" % (
        snyk_gh_repo["org_name"],
        snyk_gh_repo["full_name"]
    ))

    print("  - [%s] GitHub Status: %s [%s]" % (
        snyk_gh_repo["full_name"],
        gh_repo_status["response_code"],
        gh_repo_status["response_message"]
    ))

    if gh_repo_status["response_code"] == 404: # project no longer exists
        log_potential_delete(snyk_gh_repo["org_name"], snyk_gh_repo["full_name"])

    elif gh_repo_status["response_code"] == 200: # project has not been renamed
        print("  - [%s] Checking %d projects for any stale manifests"% (
            snyk_gh_repo["full_name"], len(snyk_repo_projects)
        ))

        if not dry_run:
            delete_stale_manifests(snyk_repo_projects)

        print("  - [%s] Adding any new manifests via Import" % snyk_gh_repo["full_name"])

        if not dry_run:
            _import_response = import_github_repo(
                snyk_gh_repo["org_id"], snyk_gh_repo["owner"], snyk_gh_repo["name"]
            )

    elif gh_repo_status["response_code"] == 301: # project has been renamed
        print("  - [%s] Adding any new manifests via Import" % snyk_gh_repo["full_name"])

        if not dry_run:
            _import_response = import_github_repo(
                snyk_gh_repo["org_id"], gh_repo_status["gh_owner"], gh_repo_status["gh_name"]
            )

            print("  - [%s] Removals pending renamed repo import..." %snyk_gh_repo["full_name"])

            for snyk_repo_project in snyk_repo_projects:
                print("     - %s:%s" % (
                    snyk_repo_project["repo_full_name"], snyk_repo_project["manifest"]
                ))
                _deletes_pending_on_import.append(
                    {
                        "old_repo": snyk_gh_repo["full_name"],
                        "new_repo": gh_repo_status["gh_owner"] + '/' + gh_repo_status["gh_name"],
                        "pending_project_id": snyk_repo_project["id"],
                        "pending_manifest": snyk_repo_project["manifest"],
                        "pending_org_id": snyk_repo_project["org_id"]
                    })

    return (_import_response, _deletes_pending_on_import)

def process_snyk_repos(snyk_gh_projects, snyk_gh_repos):
    _import_status_checks = []
    _deletes_pending_on_import = []
    # process snyk projects and get import check data
    for (i, snyk_gh_repo) in enumerate(snyk_gh_repos):

        print(f"Processing repo {str(i+1)}/{str(len(snyk_gh_repos))}")

        snyk_repo_projects = get_snyk_projects_from_github_repo(snyk_gh_repo, snyk_gh_projects)

        try:
            (import_response, pending_delete) = process_snyk_repo_projects_and_get_check_data(snyk_repo_projects, snyk_gh_repo)
        except (snyk.errors.SnykHTTPError, snyk.errors.SnykNotFoundError) as err:
            print("  - [%s] Import error: %s, skipping" % (snyk_gh_repo["org_name"], err.message))
            #log this
            REPOS_SKIPPED_ON_ERROR_FILE.write("%s,%s,%s\n" % (
                snyk_gh_repo["org_name"],
                snyk_gh_repo["repo_full_name"],
                err.message 
            ))
            continue # on error, break out of this for loop and process the next repo
        if len(import_response) > 0:
            _import_status_checks.append(import_response)
        if len(pending_delete) > 0:
            _deletes_pending_on_import.append(pending_delete)
        if not dry_run:
            time.sleep(5)

    return (_import_status_checks, _deletes_pending_on_import)

def main():
    """Main"""

    print("dry-run = %s" % dry_run)
    sys.stdout.write("Retrieving Snyk Projects...")
    sys.stdout.flush()

    snyk_orgs = []
    import_status_checks = []
    deletes_pending_on_import = []

    # if --orgId exists, use it
    # otherwise get all orgs the api user is part of
    try:
        if org_id_filter:
            snyk_orgs.append(snyk_client.organizations.get(org_id_filter))
        else:
            snyk_orgs = snyk_client.organizations.all()
    except snyk.errors.SnykHTTPError as err:
        print("\n\n%s, exiting...\n" % err.message)
        sys.exit(1)

    # build complete Snyk project list
    snyk_gh_projects = build_snyk_project_list(snyk_orgs)
    sys.stdout.write("%d" % len(snyk_gh_projects))

    # build unique repos in Snyk from project list
    snyk_gh_repos = unique_repos_from_snyk_projects(snyk_gh_projects)
    sys.stdout.write(" [%d Unique repos]\n" % len(snyk_gh_repos))

    (import_status_checks, deletes_pending_on_import) = process_snyk_repos(snyk_gh_projects, snyk_gh_repos)

    # process import status checks
    if not dry_run:
        if len(import_status_checks) > 0:
            process_import_status_checks(import_status_checks, deletes_pending_on_import)

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

    PENDING_REMOVAL_MAX_CHECKS = 45
    PENDING_REMOVAL_CHECK_INTERVAL = 20

    snyk_token = getenv("SNYK_TOKEN")
    github_token = getenv("GITHUB_TOKEN")
    args = parse_command_line_args()
    org_id_filter = args.org_id
    project_id_filter = args.project_id
    dry_run = args.dry_run

    snyk_client = SnykClient(snyk_token)

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
    COMPLETED_PROJECT_IMPORTS_FILE.write("org,repo,status\n")

    main()

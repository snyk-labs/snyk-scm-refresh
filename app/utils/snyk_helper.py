""" helper functions to interact with snyk """
# pylint: disable=invalid-name, cyclic-import
import sys
import re
import time
import snyk.errors
import common
from app.models import ImportStatus
from ..snyk_repo import SnykRepo

def app_print(org, repo, text):
    """print formatted output"""
    print(f"[org:{org}][{repo}] {text}")

def log_potential_delete(org_name, repo_name):
    """ Log potential repo deletion """
    app_print(org_name, repo_name, "Logging potential delete")
    common.POTENTIAL_DELETES_FILE.write("%s,%s\n" % (org_name, repo_name))

def get_snyk_repos_from_snyk_orgs(snyk_orgs, ARGS):
    """Build list of repositories from a given list of Snyk orgs"""
    snyk_repos = []
    snyk_projects = build_snyk_project_list(snyk_orgs, ARGS)

    repo_projects = []

    # initialize to the first repo name
    curr_repo_name = snyk_projects[0]["repo_full_name"]
    num_projects = len(snyk_projects)

    for (i, project) in enumerate(snyk_projects):
        # print("project: " + project['name'])
        if i == num_projects-1:
            snyk_repos.append(
                SnykRepo(snyk_projects[i]["repo_full_name"],
                        snyk_projects[i]["org_id"],
                        snyk_projects[i]["org_name"],
                        snyk_projects[i]["integration_id"],
                        snyk_projects[i]["origin"],
                        repo_projects)
            )

        # we encountered a new repo, or reached the end of the project list
        if project["repo_full_name"] != curr_repo_name:
            # add repo to snyk_repos
            snyk_repos.append(
                SnykRepo(snyk_projects[i-1]["repo_full_name"],
                        snyk_projects[i-1]["org_id"],
                        snyk_projects[i-1]["org_name"],
                        snyk_projects[i-1]["integration_id"],
                        snyk_projects[i-1]["origin"],
                        repo_projects)
            )
            repo_projects = [project]

        else:
            # add to project list for this repo
            repo_projects.append(project)

        curr_repo_name = project["repo_full_name"]
    return snyk_repos

def build_snyk_project_list(snyk_orgs, ARGS):
    # pylint: disable=too-many-branches
    """Build list of Snyk projects across all Snyk orgs in scope"""
    snyk_gh_projects = []
    snyk_projects = []
    project_origins = []

    if common.GITHUB_ENABLED:
        project_origins.append("github")
    if common.GITHUB_ENTERPRISE_ENABLED:
        project_origins.append("github-enterprise")

    for (i, snyk_org) in enumerate(snyk_orgs):
        print(f"({i+1}) org: {snyk_org.name}")
        try:
            if common.GITHUB_ENABLED:
                gh_integration_id = snyk_org.integrations.filter(name="github")[
                    0].id
            if common.GITHUB_ENTERPRISE_ENABLED:
                gh_enterprise_integration_id = \
                    snyk_org.integrations.filter(name="github-enterprise")[0].id
        except snyk.errors.SnykHTTPError:
            print(f"\n\nUnable to retrieve GitHub integration id for org: {snyk_org.name}, " \
                "check permissions and integration status\n\n")
            sys.exit(1)

        snyk_projects = snyk_org.projects.all()

        if ARGS.repo_name:
            snyk_projects = get_snyk_projects_for_repo(
                snyk_projects, ARGS.repo_name)

        for project in snyk_projects:
            integration_id = ''
            if project.origin in project_origins:
                if project.origin == 'github':
                    integration_id = gh_integration_id
                elif project.origin == 'github-enterprise':
                    integration_id = gh_enterprise_integration_id
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
                        "origin": project.origin,
                        "integration_id": integration_id,
                        "branch_from_name": branch_from_name,
                    }
                )

    snyk_gh_projects = sorted(
        snyk_gh_projects, key=lambda x: x['repo_full_name'])
    return snyk_gh_projects

def get_snyk_projects_for_repo(snyk_projects, repo_full_name):
    """Return snyk projects that belong to the specified repo only"""
    snyk_projects_filtered = []

    for snyk_project in snyk_projects:
        # extract the repo part of the project name
        # e.g. scotte-snyk/demo-project:package.json should return
        # 'scotte-snyk/demo-project'
        if repo_full_name == snyk_project.name.split(":")[0]:
            snyk_projects_filtered.append(snyk_project)

    return snyk_projects_filtered

def import_manifests(org_id, repo_full_name, integration_id, files=[]) -> ImportStatus:
    # pylint: disable=dangerous-default-value
    """Import a Github Repo into Snyk"""

    repo_full_name = repo_full_name.split("/")
    org = common.snyk_client.organizations.get(org_id)
    path = "org/%s/integrations/%s/import" % (org.id, integration_id)

    if len(files) > 0:
        payload = {
            "target": {"owner": repo_full_name[0], "name": repo_full_name[1], "branch": ""},
            "files": files
        }
    else:
        payload = {
            "target": {"owner": repo_full_name[0], "name": repo_full_name[1], "branch": ""}
        }

    try:
        response = org.client.post(path, payload)
    except snyk.errors.SnykHTTPError as err:
        if err.code in [502, 504]:
            print("Server error, lets try again in a minute...")
            time.sleep(60)
            try:
                response = org.client.post(path, payload)
            except snyk.errors.SnykHTTPError as err_retry:
                print(f"Still failed after retry with {str(err_retry.code)}!")
                raise
    return ImportStatus(re.search('org/.+/integrations/.+/import/(.+)',
                                  response.headers['Location']).group(1),
                        response.headers['Location'],
                        org.id,
                        org.name,
                        repo_full_name[0],
                        repo_full_name[1],
                        files,
                        [])

def delete_snyk_project(project_id, org_id):
    """Delete a single Snyk project"""

    org = common.snyk_client.organizations.get(org_id)

    try:
        project = org.projects.get(project_id)
        return project.delete()
    except snyk.errors.SnykNotFoundError:
        print(f"    - Project {project_id} not found in org {org_id} ...")
        return False

def process_import_status_checks(import_status_checks):
    # pylint: disable=too-many-nested-blocks, too-many-branches
    """
    Check status of pending import jobs
    up to PENDING_REMOVAL_MAX_CHECKS times,
    waiting PENDING_REMOVAL_CHECK_INTERVAL seconds between checks
    """

    check_count = 0
    unique_import_status_checks = []
    import_jobs_completed = []
    import_logs_completed = []

    print("Checking import statuses, polling for up to %s minutes..."
          % str((common.PENDING_REMOVAL_MAX_CHECKS * common.PENDING_REMOVAL_CHECK_INTERVAL)/60))

    # get unique import status checks with combined pending deletes (if present)
    seen_check_ids = []
    for import_status_check in import_status_checks:
        if import_status_check.import_job_id not in seen_check_ids:
            unique_import_status_checks.append(import_status_check)
            seen_check_ids.append(import_status_check.import_job_id)
        else:
            for (i, usc) in enumerate(unique_import_status_checks):
                if usc.import_job_id == import_status_check.import_job_id:
                    unique_import_status_checks[i].pending_project_deletes.extend(
                        import_status_check.pending_project_deletes)

    while check_count < common.PENDING_REMOVAL_MAX_CHECKS:
        if len(unique_import_status_checks) > len(import_jobs_completed):
            sys.stdout.write("%s batch pending\n" % (
                len(unique_import_status_checks) - len(import_jobs_completed)
            ))
            sys.stdout.flush()
            # check each import job statuses
            for import_job in unique_import_status_checks:
                if import_job.import_job_id not in import_jobs_completed:
                    import_status = get_import_status(
                        import_job.import_status_url, import_job.org_id
                    )
                    print(f"checking import job: {import_job.import_job_id}" \
                        f" [{import_status['status']}]")

                    # process each individual repo import
                    for import_status_log in import_status["logs"]:
                        uniq_import_log = import_status_log["name"] + \
                            '-' + import_status_log["created"]
                        if uniq_import_log not in import_logs_completed:
                            print("  - [%s] Import Target status: %s (%s projects)" % (
                                import_status_log["name"],
                                import_status_log["status"],
                                len(import_status_log["projects"])
                            ))
                            # if repo import status is complete, log
                            # and delete any pending waiting on this repo import
                            if import_status_log["status"] == "complete":
                                # print(import_status_log)
                                import_logs_completed.append(uniq_import_log)
                                for project in import_status_log["projects"]:
                                    app_print(import_job.org_name,
                                              import_status_log["name"],
                                              f"Imported {project['targetFile']}")
                                    common.COMPLETED_PROJECT_IMPORTS_FILE.write("%s,%s:%s,%s\n" % (
                                        import_job.org_name,
                                        import_status_log["name"],
                                        project["targetFile"],
                                        project["success"]
                                    ))

                    if import_status["status"] != "pending":
                        import_jobs_completed.append(import_job.import_job_id)
                        # print(f'import job completed with id: {import_job.import_job_id}')
                        #job completed, do the pending deletes here
                        for pending_delete in import_job.pending_project_deletes:
                            app_print(pending_delete['org_name'],
                                      pending_delete['repo_full_name'],
                                      "delete stale project [%s]" % (
                                pending_delete['id']
                            ))
                            delete_snyk_project(
                                pending_delete['id'],
                                pending_delete['org_id']
                            )
                            common.RENAMED_MANIFESTS_DELETED_FILE.write("%s,%s:%s\n" % (
                                pending_delete['org_name'],
                                pending_delete['repo_full_name'],
                                pending_delete['manifest']
                            ))

            print("Checking back in %d seconds..." %
                common.PENDING_REMOVAL_CHECK_INTERVAL)
            time.sleep(common.PENDING_REMOVAL_CHECK_INTERVAL)

        else:
            print("None Pending, Done.\n")
            return

        check_count += 1
        if check_count == common.PENDING_REMOVAL_MAX_CHECKS:
            print(
                "\nExiting with %d pending removals, logging...\n" % (
                    len(unique_import_status_checks) -
                    len(import_jobs_completed)
                )
            )
            for import_status_check in unique_import_status_checks:
                if import_status_check.import_job_id \
                        not in import_jobs_completed:
                    common.RENAMED_MANIFESTS_PENDING_FILE.write(
                        "%s,%s/%s\n" % (
                            import_status_check.org_name,
                            import_status_check.repo_owner,
                            import_status_check.repo_name
                        )
                    )
            return


def get_import_status(import_status_url, org_id):
    """Retrieve status data for a Snyk import job"""

    # extract path segment for later use
    path = re.search('.+(org/.+)', import_status_url).group(1)

    org = common.snyk_client.organizations.get(org_id)
    response = org.client.get(path)
    return response.json()

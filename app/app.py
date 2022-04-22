"""
Keep Snyk projects in sync with their corresponding SCM repositories
"""
import sys
import time
import re
import snyk.errors
import common
from app.models import ImportStatus
from app.gh_repo import (
    get_gh_repo_status,
    is_default_branch_renamed,
    is_gh_repo_truncated,
    get_git_tree_from_api
)
from app.utils.snyk_helper import (
    get_snyk_repos_from_snyk_orgs,
    app_print,
    process_import_status_checks,
    import_manifests,
    log_potential_delete,
    log_audit_large_repo_result
)

def run():
    """Begin application logic"""
    # pylint: disable=too-many-locals, too-many-branches, too-many-statements
    # pylint: disable=too-many-nested-blocks
    sys.stdout.write("Retrieving Snyk Repos")
    sys.stdout.flush()

    snyk_orgs = []

    # if --orgId exists, use it
    # otherwise get all orgs the api user is part of
    try:
        if common.ARGS.org_id:
            snyk_orgs.append(common.snyk_client.organizations.get(common.ARGS.org_id))
        else:
            snyk_orgs = common.snyk_client.organizations.all()
    except snyk.errors.SnykHTTPError as err:
        print(f"\n\n{err.message}, exiting...\n")
        sys.exit(1)

    print(f" for {len(snyk_orgs)} org(s)")

    # build snyk repo objects
    snyk_repos = get_snyk_repos_from_snyk_orgs(snyk_orgs, common.ARGS)
    len_snyk_repos = len(snyk_repos)
    sys.stdout.write(f" - {len_snyk_repos} found\n")
    if len_snyk_repos == 0:
        print("\nIf using repo-name filter, ensure it is correct\n")
        sys.exit(1)

    import_status_checks = []

    for (i, snyk_repo) in enumerate(snyk_repos):
        # snyk_repo.get_projects()
        deleted_projects = []
        is_default_renamed = False
        app_print(snyk_repo.org_name,
                  snyk_repo.full_name,
                  f"Processing {str(i+1)}/{str(len(snyk_repos))}")

        try:
            gh_repo_status = get_gh_repo_status(snyk_repo)

        except RuntimeError as err:
            raise RuntimeError("Failed to query GitHub repository!") from err

        app_print(snyk_repo.org_name,
                  snyk_repo.full_name,
                  f"Github Status {gh_repo_status.response_code}" \
                      f"({gh_repo_status.response_message}) [{snyk_repo.origin}]")

        #if snyk_repo does not still exist (removed/404), then log and skip to next repo
        if gh_repo_status.response_code == 404: # project no longer exists
            log_potential_delete(snyk_repo.org_name, snyk_repo.full_name)

        elif gh_repo_status.response_code == 200: # project exists and has not been renamed
            # if --audit-large-repos is on
            if common.ARGS.audit_large_repos:
                is_truncated_str = \
                    is_gh_repo_truncated(
                        get_git_tree_from_api(snyk_repo.full_name, snyk_repo.origin)
                    )
                log_audit_large_repo_result(
                    snyk_repo.org_name,
                    snyk_repo.full_name,
                    str(bool(is_truncated_str))
                )
                # move to next repo without processing the rest of the code
                continue
            # snyk has the wrong branch, re-import
            if gh_repo_status.repo_default_branch != snyk_repo.branch:
                app_print(snyk_repo.org_name,
                          snyk_repo.full_name,
                          f"Default branch name changed from {snyk_repo.branch}" \
                          f" -> {gh_repo_status.repo_default_branch}")
                app_print(snyk_repo.org_name,
                          snyk_repo.full_name,
                          "Checking if existing default branch was just renamed?")
                try:
                    if snyk_repo.origin == "github":
                        is_default_renamed = is_default_branch_renamed(
                            snyk_repo, gh_repo_status.repo_default_branch,
                            common.GITHUB_TOKEN)
                    elif snyk_repo.origin == "github-enterprise":
                        is_default_renamed = is_default_branch_renamed(
                            snyk_repo, gh_repo_status.repo_default_branch,
                            common.GITHUB_ENTERPRISE_TOKEN,
                            True)

                except RuntimeError as err:
                    raise RuntimeError("Failed to query GitHub repository!") from err

                if not is_default_renamed:
                    app_print(snyk_repo.org_name,
                              snyk_repo.full_name,
                              "It's a different branch, update snyk projects...")
                    updated_projects = snyk_repo.update_branch(
                        gh_repo_status.repo_default_branch,
                        common.ARGS.dry_run)
                    for project in updated_projects:
                        if not common.ARGS.dry_run:
                            app_print(snyk_repo.org_name,
                                      snyk_repo.full_name,
                                      f"Monitored branch set to " \
                                      f"{gh_repo_status.repo_default_branch} " \
                                      f"for: {project['manifest']}")
                else:
                    app_print(snyk_repo.org_name,
                              snyk_repo.full_name,
                              "Branch was just renamed, leaving as-is")
            else: #find deltas
                app_print(snyk_repo.org_name,
                          snyk_repo.full_name,
                          f"Checking {str(len(snyk_repo.snyk_projects))} " \
                          f"projects for any stale manifests")
                # print(f"snyk repo projects: {snyk_repo.snyk_projects}")
                deleted_projects = snyk_repo.delete_stale_manifests(common.ARGS.dry_run)
                for project in deleted_projects:
                    if not common.ARGS.dry_run:
                        app_print(snyk_repo.org_name,
                                  snyk_repo.full_name,
                                  f"Deleted stale manifest: {project['manifest']}")
                    else:
                        app_print(snyk_repo.org_name,
                                  snyk_repo.full_name,
                                  f"Would delete stale manifest: {project['manifest']}")

                app_print(snyk_repo.org_name,
                          snyk_repo.full_name,
                          "Checking for new manifests in source tree")

                #if not common.ARGS.dry_run:
                projects_import = snyk_repo.add_new_manifests(common.ARGS.dry_run)

                if isinstance(projects_import, ImportStatus):
                    import_status_checks.append(projects_import)
                    app_print(snyk_repo.org_name,
                              snyk_repo.full_name,
                              f"Found {len(projects_import.files)} to import")
                    for file in projects_import.files:
                        import_message = ""
                        if re.match(common.MANIFEST_PATTERN_CODE, file["path"]):
                            import_message = "Triggering code analysis via"
                        else:
                            import_message = "Importing new manifest"

                        app_print(snyk_repo.org_name,
                                  snyk_repo.full_name,
                                  f"{import_message}: {file['path']}")

        # if snyk_repo has been moved/renamed (301), then re-import the entire repo
        # with the new name and remove the old one (make optional)
        elif gh_repo_status.response_code == 301:
            app_print(snyk_repo.org_name,
                      snyk_repo.full_name,
                      f"Repo has moved to {gh_repo_status.repo_full_name}, submitting import...")
            if not common.ARGS.dry_run:
                repo_import_status = import_manifests(snyk_repo.org_id,
                                                      gh_repo_status.repo_full_name,
                                                      snyk_repo.integration_id)
                # build list of projects to delete with old name
                # only when the repo with new name has been imported
                repo_projects = snyk_repo.get_projects()
                # pylint: disable=unused-variable
                for (j, repo_project) in enumerate(repo_projects):
                    repo_projects[j]["pending_repo"] = gh_repo_status.repo_full_name

                repo_import_status.pending_project_deletes = repo_projects
                import_status_checks.append(repo_import_status)
            else:
                app_print(snyk_repo.org_name,
                          snyk_repo.full_name,
                          "Would import repo (all targets) under new name")

        else:
            app_print(snyk_repo.org_name,
                      snyk_repo.full_name,
                      f"Skipping due to invalid response")

        time.sleep(1)

    process_import_status_checks(import_status_checks)

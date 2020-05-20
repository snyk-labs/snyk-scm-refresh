def unique_import_jobs_from_status_checks(import_status_checks):
    unique_import_jobs = []
    for import_status_check in import_status_checks:
        if import_status_check["job_id"] not in {u["job_id"] for u in unique_import_jobs}:
            unique_import_jobs.append(
                {
                    "job_id": import_status_check["job_id"],
                    "import_status_url": import_status_check["import_status_url"],
                    "org_id": import_status_check["org_id"],
                    "org_name": import_status_check["org_name"]
                }
            )
    return unique_import_jobs

#def unique_repos_from_status_checks(import_status_checks):
#    status_check_repos = []
#    for import_status_check in import_status_checks:
#        import_status_check_full_name = \
#            import_status_check["owner"] + '/' + import_status_check["name"]
#        if import_status_check_full_name not in status_check_repos:
#            status_check_repos.append(import_status_check_full_name)
#    return status_check_repos

def unique_repos_from_snyk_projects(snyk_gh_projects):
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
                    "org_name": project["org_name"],
                    "gh_integration_id": project["gh_integration_id"],
                    "branch_from_name": project["branch_from_name"],
                }
            )
    return snyk_gh_repos

def get_snyk_projects_from_github_repo(snyk_gh_repo, snyk_gh_projects):
    snyk_repo_projects = list(
        filter(
            lambda x: x["repo_full_name"] == snyk_gh_repo["full_name"],
            snyk_gh_projects,
        )
    )

    return  snyk_repo_projects
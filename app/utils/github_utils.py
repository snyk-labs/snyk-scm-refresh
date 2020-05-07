import os

import requests
from github import Github, GithubException


def create_github_client():
    try:
        github_token = os.environ["GITHUB_TOKEN"]
        return Github(login_or_token=github_token)
    except KeyError as err:
        raise RuntimeError(
            "Failed to initialize GitHub client because GH_TOKEN is not set!"
        ) from err


def get_gh_repo_status(snyk_gh_repo, github_token):

    repo_owner = snyk_gh_repo["owner"]
    repo_name = snyk_gh_repo["name"]
    response_message = ""

    headers = {"Authorization": "Bearer %s"}
    headers["Authorization"] = headers["Authorization"] % (github_token)
    requestURL = "https://api.github.com/repos/" + snyk_gh_repo["full_name"]
    # print("requestURL: " + requestURL)

    try:
        response = requests.get(url=requestURL, allow_redirects=False, headers=headers)
        # print("response_code: %d" % response.status_code)
        if response.status_code == 200:
            response_message = "Match"

        elif response.status_code == 404:
            response_message = "Not Found"

        elif response.status_code == 401:
            raise RuntimeError("GitHub request is unauthorized!")

        elif response.status_code == 301:
            follow_response = requests.get(
                url=response.headers["Location"], headers=headers
            )
            if follow_response.status_code == 200:
                repo_new_full_name = follow_response.json()["full_name"]
                repo_owner = repo_new_full_name.split("/")[0]
                repo_name = repo_new_full_name.split("/")[1]
            else:
                repo_owner = ""
                repo_name = ""

            response_message = "Moved %s" % repo_name

        repo_status = {
            "response_code": response.status_code,
            "response_message": response_message,
            "gh_name": repo_name,
            "snyk_org_id": snyk_gh_repo["org_id"],
            "gh_owner": repo_owner,
        }

    except requests.exceptions.RequestException as err:
        repo_status = err.response

    return repo_status


def query_branch_checks(gh_repo):
    default_branch_name = gh_repo.default_branch
    default_branch = gh_repo.get_branch(default_branch_name)
    try:
        required_checks = default_branch.get_required_status_checks().contexts
    except GithubException:
        required_checks = []

    return required_checks

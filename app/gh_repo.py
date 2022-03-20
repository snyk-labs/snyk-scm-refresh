"""utilities for github"""
import logging
import re
import requests
from app.models import GithubRepoStatus
import common

def get_repo_manifests(snyk_repo_name, origin, skip_snyk_code):
    """retrieve list of all supported manifests in a given github repo"""
    manifests = []
    try:
        if origin == 'github':
            gh_repo = common.gh_client.get_repo(snyk_repo_name)
        elif origin == 'github-enterprise':
            gh_repo = common.gh_enterprise_client.get_repo(snyk_repo_name)
    # pylint: disable=bare-except
    except:
        if origin == 'github':
            gh_repo = common.gh_enterprise_client.get_user().get_repo(snyk_repo_name)
        elif origin == 'github-enterprise':
            gh_repo = common.gh_enterprise_client.get_user().get_repo(snyk_repo_name)

    contents = gh_repo.get_git_tree(gh_repo.default_branch, True).tree

    while contents:
        file_content = contents.pop(0)
        if passes_manifest_filter(file_content.path, skip_snyk_code):
            manifests.append(file_content.path)
        if re.match(common.MANIFEST_PATTERN_CODE, file_content.path):
            skip_snyk_code = True
    #print(manifests)
    return manifests

def passes_manifest_filter(path, skip_snyk_code=False):
    """ check if given path should be imported based
        on configured search and exclusion filters """

    passes_filter = False
    if (common.PROJECT_TYPE_ENABLED_SCA and
            re.match(common.MANIFEST_PATTERN_SCA, path)):
        passes_filter = True
        # print('passes SCA filter true')
    if (common.PROJECT_TYPE_ENABLED_CONTAINER and
            re.match(common.MANIFEST_PATTERN_CONTAINER, path)):
        passes_filter = True
        # print('passes CONTAINER filter true')
    if (common.PROJECT_TYPE_ENABLED_IAC and
            re.match(common.MANIFEST_PATTERN_IAC, path)):
        passes_filter = True
        # print('passes IAC filter true')
    if (common.PROJECT_TYPE_ENABLED_CODE and
            re.match(common.MANIFEST_PATTERN_CODE, path)):
        if not skip_snyk_code:
            passes_filter = True
            # print('passes CODE filter true')
    if re.match(common.MANIFEST_PATTERN_EXCLUSIONS, path):
        passes_filter = False

    return passes_filter

def get_gh_repo_status(snyk_gh_repo):
    # pylint: disable=too-many-branches
    """detect if repo still exists, has been removed, or renamed"""
    repo_owner = snyk_gh_repo.full_name.split("/")[0]
    repo_name = snyk_gh_repo.full_name.split("/")[1]
    response_message = ""
    response_status_code = ""
    repo_default_branch = ""

    # logging.debug(f"snyk_gh_repo origin: {snyk_gh_repo.origin}")

    if snyk_gh_repo.origin == "github":
        github_token = common.GITHUB_TOKEN
    elif snyk_gh_repo.origin == "github-enterprise":
        github_token = common.GITHUB_ENTERPRISE_TOKEN

    headers = {"Authorization": "Bearer %s"}
    headers["Authorization"] = headers["Authorization"] % (github_token)
    if snyk_gh_repo.origin == "github" or \
        (snyk_gh_repo.origin == "github-enterprise" and \
            common.USE_GHE_INTEGRATION_FOR_GH_CLOUD):
        request_url = f"https://api.github.com/repos/{snyk_gh_repo['full_name']}"
        # print("requestURL: " + requestURL)
    elif snyk_gh_repo.origin == "github-enterprise":
        request_url = f"https://{common.GITHUB_ENTERPRISE_HOST}" \
        f"/api/v3/repos/{snyk_gh_repo['full_name']}"
    try:
        response = requests.get(url=request_url, allow_redirects=False, headers=headers)
        # logging.debug("response_code: %d" % response.status_code)
        # logging.debug(f"response default branch -> {response.json()['default_branch']}")

        response_status_code = response.status_code

        if response.status_code == 200:
            response_message = "Match"
            repo_default_branch = response.json()['default_branch']

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

            response_message = f"Moved to {repo_name}"

    except requests.exceptions.RequestException as err:
        # make sure it gets logged in log file when in debug mode
        logging.debug(f"{err}")

        response_status_code = "ERROR"
        response_message = f"{err}"

    finally:
        repo_status = GithubRepoStatus(
            response_status_code,
            response_message,
            repo_name,
            snyk_gh_repo["org_id"],
            repo_owner,
            f"{repo_owner}/{repo_name}",
            repo_default_branch
        )
    return repo_status

def is_default_branch_renamed(snyk_gh_repo, new_branch, github_token, github_enterprise=False):
    """detect if default branch has been renamed"""
    is_renamed = False
    headers = {"Authorization": "Bearer %s"}
    headers["Authorization"] = headers["Authorization"] % (github_token)
    if not github_enterprise:
        request_url = f"https://api.github.com/repos/{snyk_gh_repo.full_name}" \
            f"/branches/{snyk_gh_repo.branch}"
        #print("requestURL: " + request_url)
    else:
        request_url = f"https://{common.GITHUB_ENTERPRISE_HOST}" \
        f"/api/v3/repos/{snyk_gh_repo.full_name}/branches/{snyk_gh_repo.branch}"
    try:
        response = requests.get(url=request_url, allow_redirects=False, headers=headers)

        if response.status_code in (301, 302):
            print('redirect response url: ' + response.headers["Location"])
            if str(response.headers["Location"]).endswith(f"/{new_branch}"):
                # print('the redirect is pointing to the new branch')
                is_renamed = True
            # else:
            #    print('the redirect is pointing to a different branch')
        else:
            is_renamed = False
    except requests.exceptions.RequestException as err:
        print(f"exception trying to determine renamed status: {err.response}")
        #log this to file
        is_renamed = True

    return is_renamed

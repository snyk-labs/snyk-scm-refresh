"""utilities for github"""
import re
import requests
import common

def get_repo_manifests(snyk_repo_name, origin):
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
    #print(contents)

    while contents:
        file_content = contents.pop(0)
        if passes_manifest_filter(file_content.path):
            manifests.append(file_content.path)
    return manifests

def passes_manifest_filter(path):
    """ check if given path should be imported based
        on configured search and exclusion filters """
    return bool(re.match(common.MANIFEST_REGEX_PATTERN, path) and
            not re.match(common.MANIFEST_EXCLUSION_REGEX_PATTERN, path))

def get_gh_repo_status(snyk_gh_repo, github_token, github_enterprise=False):
    """detect if repo still exists, has been removed, or renamed"""
    repo_owner = snyk_gh_repo["owner"]
    repo_name = snyk_gh_repo["name"]
    response_message = ""
    repo_default_branch = ""

    headers = {"Authorization": "Bearer %s"}
    headers["Authorization"] = headers["Authorization"] % (github_token)
    if not github_enterprise:
        request_url = f"https://api.github.com/repos/{snyk_gh_repo['full_name']}"
        # print("requestURL: " + requestURL)
    else:
        request_url = f"https://{common.GITHUB_ENTERPRISE_HOST}" \
        f"/api/v3/repos/{snyk_gh_repo['full_name']}"
    try:
        response = requests.get(url=request_url, allow_redirects=False, headers=headers)
        # print("response_code: %d" % response.status_code)
        # print(f"response default branch -> {response.json()['default_branch']}")

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

            response_message = "Moved to %s" % repo_name

        repo_status = {
            "response_code": response.status_code,
            "response_message": response_message,
            "repo_name": repo_name,
            "snyk_org_id": snyk_gh_repo["org_id"],
            "repo_owner": repo_owner,
            "repo_full_name": f"{repo_owner}/{repo_name}",
            "repo_default_branch": repo_default_branch
        }

    except requests.exceptions.RequestException as err:
        repo_status = err.response

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

        if response.status_code == 301 or response.status_code == 302:
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

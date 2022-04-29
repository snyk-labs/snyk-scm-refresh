"""utilities for github"""
import logging
import re
import sys
import subprocess
import requests
from app.models import GithubRepoStatus
from app.utils.github_utils import (
    get_github_client,
    get_github_repo
)
import common


# suppess InsecureRequestWarning when using --skip-scm-validation option
# due to pylint bug
# https://github.com/PyCQA/pylint/issues/4584)
# pylint: disable=no-member
requests.packages.urllib3.disable_warnings()

# pylint: disable=invalid-name
state = {
    "tree_already_retrieved": False,
    "manifests": []
}

def get_git_tree_from_clone(repo_name, origin):
    """
    get git tree for large repos by performing
    a shallow clone 'git clone --depth 1'
    """

    tree_full_paths = []

    gh_client = get_github_client(origin)
    gh_repo = get_github_repo(gh_client, repo_name)

    # check if git exists on the system
    subprocess.run(["command", "-v", "git"], check=True, stdout=subprocess.DEVNULL)

    name = gh_repo.name
    clone_url = gh_repo.clone_url
    default_branch = gh_repo.default_branch

    GIT_CLONE_PATH = f"{common.GIT_CLONE_TEMP_DIR}/{name}"

    # check that GIT_CLONE_PATH is set safely for deletion
    if re.match(f'{common.GIT_CLONE_TEMP_DIR}/.+', GIT_CLONE_PATH) and \
        re.match(rf'\/.+\/.+', GIT_CLONE_PATH):
        pass
    else:
        sys.exit(f"could not determine that the temp cloning directory"
                 f"{GIT_CLONE_PATH} was set properly, exiting...")

    print(f"  - shallow cloning {name} from {clone_url} to {GIT_CLONE_PATH}")

    # clone the repo locally
    subprocess.run(["rm", "-fr", f"{GIT_CLONE_PATH}"], check=True)
    subprocess.run(
        ["git", "clone", "--depth", "1", clone_url],
        check=True,
        cwd=common.GIT_CLONE_TEMP_DIR
    )

    print("  - Loading tree from local git structure")

    git_tree = subprocess.run(
        [
            "git",
            "ls-tree",
            "-r",
            default_branch
        ],
        capture_output=True,
        check=True,
        text=True,
        cwd=f"{GIT_CLONE_PATH}"
    )

    print(f"  - removing cloned files in /tmp...")
    subprocess.run(["rm", "-fr", f"{GIT_CLONE_PATH}"], check=True)

    git_tree_lines = git_tree.stdout.splitlines()
    print(f"  - found {len(git_tree_lines)} tree items ...")

    for line in git_tree_lines:
        sha, path = [line.split()[i] for i in (2, 3)]
        tree_full_paths.append({
            "sha": sha,
            "path": path
        })

    return tree_full_paths

def is_gh_repo_truncated(gh_tree_response) -> bool:
    """ check if repo is truncated """
    #pylint: disable=protected-access
    return gh_tree_response._rawData['truncated']

def get_git_tree_from_api(repo_name, origin):
    """ get git tree for repo via API call """
    gh_client = get_github_client(origin)
    gh_repo = get_github_repo(gh_client, repo_name)

    return gh_repo.get_git_tree(gh_repo.default_branch, True)

def get_repo_manifests(snyk_repo_name, origin, skip_snyk_code):
    """retrieve list of all supported manifests in a given github repo"""

    if state['tree_already_retrieved']:
        state['tree_already_retrieved'] = False
        return state['manifests']

    state['manifests'] = []

    tree_response = get_git_tree_from_api(snyk_repo_name, origin)

    contents = tree_response.tree

    is_truncated_str = is_gh_repo_truncated(tree_response)

    if is_truncated_str:
        # repo too large to get try via API, just clone it
        print(f"  - Large repo detected, falling back to cloning. "
              f"This may take a few minutes ...")
        contents = get_git_tree_from_clone(snyk_repo_name, origin)
        # print(f"tree contents: {contents}")

    while contents:
        tree_element = contents.pop(0)
        # print(f"tree_element: {tree_element}")
        if is_truncated_str:
            tree_element_sha = tree_element['sha']
            tree_element_path = tree_element['path']
        else:
            tree_element_sha = tree_element.sha
            tree_element_path = tree_element.path
        full_path = {
            "sha": tree_element_sha,
            "path": tree_element_path
        }
        if passes_manifest_filter(full_path['path'], skip_snyk_code):
            #print(f"appending to manifests to check")
            state['manifests'].append(full_path['path'])
        if re.match(common.MANIFEST_PATTERN_CODE, full_path['path']):
            skip_snyk_code = True

    state['tree_already_retrieved'] = True
    return state['manifests']

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
        response = requests.get(url=request_url,
                                allow_redirects=False,
                                headers=headers,
                                verify=common.VERIFY_TLS)
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
                url=response.headers["Location"],
                headers=headers,
                verify=common.VERIFY_TLS
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

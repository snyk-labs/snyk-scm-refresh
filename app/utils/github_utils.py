"""
methods for creating github or
github enterprise clients
"""
from github import Github
import common

# pylint: disable=invalid-name
def create_github_client(GITHUB_TOKEN, VERIFY_TLS):
    """ return a github client for given token """
    try:
        return Github(login_or_token=GITHUB_TOKEN, verify=VERIFY_TLS)
    except KeyError as err:
        raise RuntimeError(
            "Failed to initialize GitHub client because GITHUB_TOKEN is not set!"
        ) from err

def create_github_enterprise_client(GITHUB_ENTERPRISE_TOKEN, GITHUB_ENTERPRISE_HOST, VERIFY_TLS):
    """ return a github enterprise client for given token/host """
    try:
        return Github(base_url=f"https://{GITHUB_ENTERPRISE_HOST}/api/v3", \
            login_or_token=GITHUB_ENTERPRISE_TOKEN, verify=VERIFY_TLS)
    except KeyError as err:
        raise RuntimeError(
            "Failed to initialize GitHub client because GITHUB_ENTERPRISE_TOKEN is not set!"
        ) from err

def get_github_client(origin):
    """ get the right github client depending on intergration type """
    #pylint: disable=no-else-return
    if origin == 'github':
        return common.gh_client
    elif origin == 'github-enterprise':
        return common.gh_enterprise_client
    else:
        raise Exception(f"could not get github client for type: {origin}")

def get_github_repo(gh_client, repo_name):
    """ get a github repo by name """
    try:
        return gh_client.get_repo(repo_name)
    # pylint: disable=bare-except
    except:
        return gh_client.get_user().get_repo(repo_name)
 
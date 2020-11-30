"""
methods for creating github or
github enterprise clients
"""
from github import Github

# pylint: disable=invalid-name
def create_github_client(GITHUB_TOKEN):
    """ return a github client for given token """
    try:
        return Github(login_or_token=GITHUB_TOKEN)
    except KeyError as err:
        raise RuntimeError(
            "Failed to initialize GitHub client because GITHUB_TOKEN is not set!"
        ) from err

def create_github_enterprise_client(GITHUB_ENTERPRISE_TOKEN, GITHUB_ENTERPRISE_HOST):
    """ return a github enterprise client for given token/host """
    try:
        return Github(base_url=f"https://{GITHUB_ENTERPRISE_HOST}/api/v3", \
            login_or_token=GITHUB_ENTERPRISE_TOKEN)
    except KeyError as err:
        raise RuntimeError(
            "Failed to initialize GitHub client because GITHUB_ENTERPRISE_TOKEN is not set!"
        ) from err

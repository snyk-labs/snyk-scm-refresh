"""test suite for snyk_scm_refresh.py"""
import os
import pytest
from snyk.models import Project
import common
from app.snyk_repo import SnykRepo
from app.models import GithubRepoStatus

from app.gh_repo import (
    get_gh_repo_status,
    passes_manifest_filter,
)
from app.utils.snyk_helper import (
    get_snyk_projects_for_repo,
    get_snyk_repos_from_snyk_projects
)

class MockResponse:
    """ mock response for github check """
    def __init__(self, status_code):
        self.status_code = status_code
        self.headers = {"Location": "test_location"}

    def json(self):
        response = {"full_name": "new_owner/new_repo", "default_branch": "master"}
        return response

@pytest.mark.parametrize(
    "status_code, response_message, repo, name, owner, default_branch",
    [
        (200, "Match", "test_org/test_repo", "test_repo", "test_owner", "master"),
        (301, "Moved to new_repo", "new_owner/new_repo", "new_repo", "new_owner", ""),
        (404, "Not Found", "test_org/test_repo", None, None, "")
    ],
)
def test_get_gh_repo_status_github(mocker, status_code, response_message, repo, name, owner, default_branch):

    # TODO: assumes a successful redirect for the 301 case
    mocker.patch(
        "requests.get", side_effect=[MockResponse(status_code), MockResponse(200)]
    )
    mocker.patch.dict(os.environ, {'GITHUB_ENTERPRISE_TOKEN': '1234', 'GITHUB_ENTERPRISE_HOST':common.GITHUB_CLOUD_API_HOST})

    snyk_repo_github = SnykRepo(
        'new_owner/new_repo',
        "1234-5678",
        "new_owner",
        "12345",
        "github",
        "master",
        []
    )

    repo_status = GithubRepoStatus(
        status_code,
        response_message,
        snyk_repo_github["full_name"].split("/")[1],
        snyk_repo_github["org_id"],
        snyk_repo_github["full_name"].split("/")[0],
        snyk_repo_github["full_name"],
        default_branch
    )

    assert get_gh_repo_status(snyk_repo_github) == repo_status

@pytest.mark.parametrize(
    "status_code, response_message, repo, name, owner, default_branch",
    [
        (200, "Match", "test_org/test_repo", "test_repo", "test_owner", "master"),
        (301, "Moved to new_repo", "new_owner/new_repo", "new_repo", "new_owner", ""),
        (404, "Not Found", "test_org/test_repo", None, None, "")
    ],
)
def test_get_gh_repo_status_github_enterprise_cloud(mocker, status_code, response_message, repo, name, owner, default_branch):

    # TODO: assumes a successful redirect for the 301 case
    mocker.patch(
        "requests.get", side_effect=[MockResponse(status_code), MockResponse(200)]
    )
    mocker.patch.dict(os.environ, {'GITHUB_ENTERPRISE_TOKEN': '1234', 'GITHUB_ENTERPRISE_HOST':common.GITHUB_CLOUD_API_HOST})

    snyk_repo_github_enterprise = SnykRepo(
        'new_owner/new_repo',
        "1234-5678",
        "new_owner",
        "12345",
        "github-enterprise",
        "master",
        []
    )

    repo_status = GithubRepoStatus(
        status_code,
        response_message,
        snyk_repo_github_enterprise["full_name"].split("/")[1],
        snyk_repo_github_enterprise["org_id"],
        snyk_repo_github_enterprise["full_name"].split("/")[0],
        snyk_repo_github_enterprise["full_name"],
        default_branch
    )

    assert get_gh_repo_status(snyk_repo_github_enterprise) == repo_status

def test_get_gh_repo_status_unauthorized(mocker):
    """ test handling unauthorized token """
    mocker.patch(
        "requests.get", side_effect=[MockResponse(401)]
    )

    mocker.patch.dict(os.environ, {'GITHUB_TOKEN': 'test_token'})

    snyk_repo = SnykRepo(
        'test_org/test_repo',
        "1234-5678",
        "new_owner",
        "12345",
        "github",
        "master",
        []
    )

    with pytest.raises(RuntimeError):
        get_gh_repo_status(snyk_repo)

def test_get_snyk_repos_from_snyk_projects():
    """ test generating unique repos from project list """

    snyk_gh_projects = [
    {
        "id": "12345",
        "name": "scotte-snyk/test-project-1:package.json",
        "repo_full_name": "scotte-snyk/test-project-1",
        "repo_owner": "scotte-snyk",
        "repo_name": "test-project-1",
        "manifest": "package.json",
        "org_id": "12345",
        "org_name": "scotte-snyk",
        "origin": "github",
        "type": "npm",
        "integration_id": "66d7ebef-9b36-464f-889c-b92c9ef5ce12",
        "branch_from_name": "",
        "branch": "master"
    },
    {
        "id": "12345",
        "name": "scotte-snyk/test-project-2:package.json",
        "repo_full_name": "scotte-snyk/test-project-2",
        "repo_owner": "scotte-snyk",
        "repo_name": "test-project-2",
        "manifest": "package.json",
        "org_id": "12345",
        "org_name": "scotte-snyk",
        "origin": "github",
        "type": "npm",
        "integration_id": "66d7ebef-9b36-464f-889c-b92c9ef5ce12",
        "branch_from_name": "",
        "branch": "master"
    },
    ]

    snyk_repos_from_snyk_projects = [
        SnykRepo(
            'scotte-snyk/test-project-1',
            "12345",
            "scotte-snyk",
            "66d7ebef-9b36-464f-889c-b92c9ef5ce12",
            "github",
            "master",
            [snyk_gh_projects[0]]
        ),
        SnykRepo(
            'scotte-snyk/test-project-2',
            "12345",
            "scotte-snyk",
            "66d7ebef-9b36-464f-889c-b92c9ef5ce12",
            "github",
            "master",
            [snyk_gh_projects[1]]
        )
    ]

    assert str(get_snyk_repos_from_snyk_projects(snyk_gh_projects)) == str(snyk_repos_from_snyk_projects)

def test_get_snyk_project_for_repo():
    """ test collecting projects for a repo """

    class TestModels(object):
    #@pytest.fixture
        def organization(self):
            org = Organization(
                name="My Other Org", id="a04d9cbd-ae6e-44af-b573-0556b0ad4bd2"
            )
            org.client = SnykClient("token")
            return org

        def base_url(self):
            return "https://snyk.io/api/v1"

        def organization_url(self, base_url, organization):
            return "%s/org/%s" % (base_url, organization.id)

    snyk_projects = [
        Project(name='scotte-snyk/test-project-1:package.json',
                organization=TestModels.organization,
                id='66d7ebef-9b36-464f-889c-b92c9ef5ce12',
                created='2020-07-27T20:09:02.150Z',
                origin='github',
                type='pip',
                readOnly=False,
                testFrequency='daily',
                totalDependencies=32,
                lastTestedDate='2020-07-28T07:15:24.981Z',
                browseUrl='https://app.snyk.io/org/scott.esbrandt-ww8' \
                    '/project/66d7ebef-9b36-464f-889c-b92c9ef5ce12',
                issueCountsBySeverity={"low": 8, "high": 13, "medium": 15},
                imageTag='0.0.0',
                imageId=None,
                isMonitored=True
        ),
        Project(name='scotte-snyk/test-project-1',
                organization=TestModels.organization,
                id='66d7ebef-9b36-464f-889c-b92c9ef5ce12',
                created='2020-07-27T20:09:02.150Z',
                origin='github',
                type='sast',
                readOnly=False,
                testFrequency='daily',
                totalDependencies=32,
                lastTestedDate='2020-07-28T07:15:24.981Z',
                browseUrl='https://app.snyk.io/org/scott.esbrandt-ww8' \
                    '/project/66d7ebef-9b36-464f-889c-b92c9ef5ce12',
                issueCountsBySeverity={"low": 8, "high": 13, "medium": 15},
                imageTag='0.0.0',
                imageId=None,
                isMonitored=True
        ),
        Project(name='scotte-snyk/test-project-2:requirements.txt',
                organization=TestModels.organization,
                id='93b82d1f-1544-45c9-b3bc-86e799c7225b',
                created='2020-07-27T20:08:44.903Z',
                origin='github',
                type='npm',
                readOnly=False,
                testFrequency='daily',
                totalDependencies=52,
                lastTestedDate='2020-07-28T01:09:27.480Z',
                browseUrl='https://app.snyk.io/org/scott.esbrandt-ww8' \
                    '/project/93b82d1f-1544-45c9-b3bc-86e799c7225b',
                issueCountsBySeverity={"low": 8, "high": 13, "medium": 15},
                imageTag='1.0.0',
                imageId=None,
                isMonitored=True
        )
    ]

    snyk_projects_filtered = [snyk_projects[0],snyk_projects[1]]

    assert get_snyk_projects_for_repo(snyk_projects, \
        "scotte-snyk/test-project-1") == snyk_projects_filtered

def test_passes_manifest_filter():
    path_fail_1 = "/__test__/path/project.csproj"
    path_fail_2 = "/node_modules/some/package.json"
    path_pass_1 = "package.json"
    path_pass_2 = "requirements-test.txt"
    path_fail_3 = "tests/vuln-in-git/Gemfile.lock"
    assert passes_manifest_filter(path_fail_1) == False
    assert passes_manifest_filter(path_pass_1) == True
    assert passes_manifest_filter(path_fail_2) == False
    assert passes_manifest_filter(path_pass_2) == True
    assert passes_manifest_filter(path_fail_3) == False

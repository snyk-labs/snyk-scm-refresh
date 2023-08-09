"""test suite for snyk_scm_refresh.py"""
import os
import pytest
import random
import string
import snyk
from snyk.models import Organization
from snyk.models import Project
import common
from app.snyk_repo import SnykRepo
from app.models import GithubRepoStatus
from _version import __version__

from app.gh_repo import (
    get_gh_repo_status,
    passes_manifest_filter,
)
from app.utils.snyk_helper import (
    get_snyk_projects_for_repo,
    get_snyk_repos_from_snyk_projects,
    import_manifests
)

USER_AGENT = f"pysnyk/snyk_services/snyk_scm_refresh/{__version__}"

class MockResponse:
    """ mock response for github check """
    def __init__(self, status_code):
        self.status_code = status_code
        self.headers = {"Location": "test_location"}

    def json(self):
        response = {"full_name": "new_owner/new_repo", "default_branch": "master", "archived": False}
        return response

@pytest.mark.parametrize(
    "status_code, response_message, repo, name, owner, default_branch, archived",
    [
        (200, "Match", "test_org/test_repo", "test_repo", "test_owner", "master", False),
        (301, "Moved to new_repo", "new_owner/new_repo", "new_repo", "new_owner", "", False),
        (404, "Not Found", "test_org/test_repo", None, None, "", False)
    ],
)
def test_get_gh_repo_status_github(mocker, status_code, response_message, repo, name, owner, default_branch, archived):

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
        default_branch,
        archived
    )

    assert get_gh_repo_status(snyk_repo_github) == repo_status

@pytest.mark.parametrize(
    "status_code, response_message, repo, name, owner, default_branch, archived",
    [
        (200, "Match", "test_org/test_repo", "test_repo", "test_owner", "master", False),
        (301, "Moved to new_repo", "new_owner/new_repo", "new_repo", "new_owner", "", False),
        (404, "Not Found", "test_org/test_repo", None, None, "", False)
    ],
)
def test_get_gh_repo_status_github_enterprise_cloud(mocker, status_code, response_message, repo, name, owner, default_branch, archived):

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
        default_branch,
        archived
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
        "branch": "master",
        "is_monitored": True
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
        "branch": "master",
        "is_monitored": True
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
            org.client = snyk.SnykClient("token", user_agent=USER_AGENT)
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
                issueCountsBySeverity={"low": 8, "high": 13, "medium": 15},
                isMonitored=True,
                branch='main',
                remoteRepoUrl='scotte-snyk/test-project-1'
        ),
        Project(name='scotte-snyk/test-project-1',
                organization=TestModels.organization,
                id='66d7ebef-9b36-464f-889c-b92c9ef5ce12',
                created='2020-07-27T20:09:02.150Z',
                origin='github',
                type='sast',
                readOnly=False,
                testFrequency='daily',
                issueCountsBySeverity={"low": 8, "high": 13, "medium": 15},
                isMonitored=True,
                branch='main',
                remoteRepoUrl='scotte-snyk/test-project-1'
        ),
        Project(name='scotte-snyk/test-project-2:requirements.txt',
                organization=TestModels.organization,
                id='93b82d1f-1544-45c9-b3bc-86e799c7225b',
                created='2020-07-27T20:08:44.903Z',
                origin='github',
                type='npm',
                readOnly=False,
                testFrequency='daily',
                issueCountsBySeverity={"low": 8, "high": 13, "medium": 15},
                isMonitored=True,
                branch='main',
                remoteRepoUrl='scotte-snyk/test-project-2'
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

@pytest.fixture
def snyk_projects_fixture():
    class TestModels(object):
        # @pytest.fixture
        def organization(self):
            org = Organization(
                name="My Other Org", id="a04d9cbd-ae6e-44af-b573-0556b0ad4bd2"
            )
            org.client = SnykClient("token", user_agent=USER_AGENT)
            return org

        def base_url(self):
            return "https://snyk.io/api/v1"

        def organization_url(self, base_url, organization):
            return "%s/org/%s" % (base_url, organization.id)

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
        "branch": "master",
        "is_monitored": True
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
        "branch": "master",
        "is_monitored": False
    },
    ]

    snyk_repo_github_enterprise = SnykRepo(
        'new_owner/new_repo',
        "1234-5678",
        "new_owner",
        "12345",
        "github-enterprise",
        "master",
        snyk_gh_projects
    )
    return snyk_repo_github_enterprise


def test_archived_repo_delete(snyk_projects_fixture, mocker):
    mock = mocker.patch(
        "app.utils.snyk_helper.delete_snyk_project"
    )
    snyk_projects_fixture.delete_manifests(dry_run=False)
    assert mock.called_once


def test_archived_repo_deactivate(snyk_projects_fixture, mocker):
    mock = mocker.patch(
        "app.utils.snyk_helper.deactivate_snyk_project"
    )
    snyk_projects_fixture.deactivate_manifests(dry_run=False)
    assert mock.called_once


def test_unarchived_repo_reactivate(snyk_projects_fixture, mocker):
    mock = mocker.patch(
        "app.utils.snyk_helper.activate_snyk_project"
    )
    snyk_projects_fixture.activate_manifests(dry_run=False)
    assert mock.called
    
def test_import_manifest_exceeds_limit(mocker):
    """
    Pytest snyk_helper.import_manifest exceeding limit of manifest projects
    """
    # refer to ie-playground org
    org_id = "39ddc762-b1b9-41ce-ab42-defbe4575bd6"
    repo_full_name = "snyk-playground/java-goof"
    integration_id = "5881e5b0-308f-4a1b-9bcb-38e3491872e0"
    files = []

    # follow snyk_repo.add_new_manifests appending manifest path
    for x in range(common.MAX_IMPORT_MANIFEST_PROJECTS + 1):
        files.append(dict({"path": ''.join(random.choices(string.ascii_lowercase, k=5)) + ".tf"}))

    mocker.patch.dict(os.environ, {'GITHUB_TOKEN': '1234'})
    org = Organization(
        name="My Other Org", id=org_id, slug="myotherorg", url=f"https://snyk.io/api/v1/org/{org_id}"
    )
    org.client = snyk.SnykClient("token", user_agent=USER_AGENT)
    mocker.patch("snyk.managers.OrganizationManager.get", return_value=org)
    mocker.patch("snyk.models.Organization.client", return_value=org.client)

    # run assertion mock client will post request and hit SnykHTTPError
    with pytest.raises(snyk.errors.SnykHTTPError):
        import_manifests(org_id, repo_full_name, integration_id, files)

    # assert csv contains header and a skipped manifest file path
    common.MANIFESTS_SKIPPED_ON_LIMIT_FILE.close()
    with open("snyk-scm-refresh_manifests-skipped-on-limit.csv", 'r') as fp:
        num_lines = len(fp.readlines())
    assert num_lines == 2

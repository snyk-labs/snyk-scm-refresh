"""test suite for snyk_scm_refresh.py"""
import pytest
from snyk.models import Project

from app.gh_repo import get_gh_repo_status
from app.utils.snyk_helper import get_snyk_projects_for_repo

class MockResponse:
    """ mock response for github check """
    def __init__(self, status_code):
        self.status_code = status_code
        self.headers = {"Location": "test_location"}

    def json(self):
        response = {"full_name": "new_owner/new_repo"}
        return response

@pytest.mark.parametrize(
    "status_code, response_message, repo, name, owner",
    [
        (200, "Match", "test_org/test_repo", "test_repo", "test_owner"),
        (301, "Moved to new_repo", "new_owner/new_repo", "new_repo", "new_owner"),
        (404, "Not Found", "test_org/test_repo", None, None)
    ],
)
def test_get_gh_repo_status(mocker, status_code, response_message, repo, name, owner):

    # TODO: assumes a successful redirect for the 301 case
    mocker.patch(
        "requests.get", side_effect=[MockResponse(status_code), MockResponse(200)]
    )

    snyk_repo = {
        "full_name": 'new_owner/new_repo',
        "owner":'new_owner',
        "name": 'new_repo',
        "org_id": "1234-5678",
        "gh_integration_id": "12345",
        "branch_from_name": "",
    }

    repo_status = {
        "response_code": status_code,
        "response_message": response_message,
        "repo_name": snyk_repo["name"],
        "snyk_org_id": snyk_repo["org_id"],
        "repo_owner": snyk_repo["owner"],
        "repo_full_name": snyk_repo["full_name"]
    }

    assert get_gh_repo_status(snyk_repo, "test_token") == repo_status

def test_get_gh_repo_status_unauthorized(mocker):
    """ test handling unauthorized token """
    mocker.patch(
        "requests.get", side_effect=[MockResponse(401)]
    )

    snyk_repo = {
        "full_name": 'test_org/test_repo',
        "owner":'test_org',
        "name": 'test_repo',
        "org_id": "1234-5678",
        "gh_integration_id": "12345",
        "branch_from_name": "",
    }

    with pytest.raises(RuntimeError):
        get_gh_repo_status(snyk_repo, "test_token")

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
                imageId=None
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
                imageId=None
        )
    ]

    snyk_projects_filtered = [snyk_projects[0]]

    assert get_snyk_projects_for_repo(snyk_projects, \
        "scotte-snyk/test-project-1") == snyk_projects_filtered
    
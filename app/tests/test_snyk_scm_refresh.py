import pytest

from snyk_scm_refresh import get_gh_repo_status


class MockResponse:
    def __init__(self, status_code):
        self.status_code = status_code
        self.headers = {"Location": "test_location"}

    def json(self):
        response = {"full_name": "new_owner/new_repo"}
        return response


@pytest.fixture(autouse=True)
def no_requests(mocker):
    mocker.patch("github.Github")
    mocker.patch("snyk.SnykClient")
    mocker.patch("requests.sessions.Session.request")


@pytest.mark.parametrize(
    "status_code, response_message, repo, name, owner",
    [
        (200, "Match", "test_org/test_repo", "test_repo", "test_owner"),
        (301, "Moved new_repo", "new_owner/new_repo", "new_repo", "new_owner"),
        (404, "Not Found", "test_org/test_repo", None, None)
    ],
)
def test_get_gh_repo_status(mocker, status_code, response_message, repo, name, owner):

    # TODO: assumes a successful redirect for the 301 case
    mocker.patch(
        "requests.get", side_effect=[MockResponse(status_code), MockResponse(200)]
    )

    snyk_repo = {
        "full_name": repo,
        "owner": owner,
        "name": name,
        "org_id": "1234-5678",
        "gh_integration_id": "12345",
        "branch_from_name": "",
    }

    repo_status = {
        "response_code": status_code,
        "response_message": response_message,
        "gh_name": snyk_repo["name"],
        "snyk_org_id": snyk_repo["org_id"],
        "gh_owner": snyk_repo["owner"],
    }

    assert get_gh_repo_status(snyk_repo, "test_token") == repo_status

def test_get_gh_repo_status_unauthorized(mocker):
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

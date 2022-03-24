"""custom data objects"""
from dataclasses import dataclass
from typing import List

@dataclass
class ImportFile:
    """File being imported"""
    path: str

@dataclass
class PendingDelete:
    """Projects needing deletion"""
    project_id: str
    project_name: str
    org_id: str
    org_name: str
    pending_repo: str

@dataclass
class ImportStatus:
    """Import job response"""
    # pylint: disable=too-many-instance-attributes
    import_job_id: str
    import_status_url: str
    org_id: str
    org_name: str
    repo_owner: str
    repo_name: str
    files: List[ImportFile]
    pending_project_deletes: List[PendingDelete]

@dataclass
class GithubRepoStatus:
    """Status of a Github repository"""
    response_code: str
    response_message: str
    repo_name: str
    org_id: str
    repo_owner: str
    repo_full_name: str
    repo_default_branch: str
    
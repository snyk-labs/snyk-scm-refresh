"""custom data objects"""
from dataclasses import dataclass
from typing import List

@dataclass
class ImportFile:
    """type definition for files being imported"""
    path: str

@dataclass
class PendingDelete:
    """type definition for projects needing deletion"""
    project_id: str
    project_name: str
    org_id: str
    org_name: str
    pending_repo: str

@dataclass
class ImportStatus:
    """type definition for import job response"""
    # pylint: disable=too-many-instance-attributes
    import_job_id: str
    import_status_url: str
    org_id: str
    org_name: str
    repo_owner: str
    repo_name: str
    files: List[ImportFile]
    pending_project_deletes: List[PendingDelete]

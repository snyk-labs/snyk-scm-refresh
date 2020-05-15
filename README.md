# snyk-scm-refresh
[![Known Vulnerabilities](https://snyk.io/test/github/snyk-tech-services/snyk-scm-refresh/badge.svg)](https://snyk.io/test/github/snyk-tech-services/snyk-scm-refresh)

Keeps Snyk projects in sync with their associated Github repos

### Use cases:
For repos with at least 1 project already in Snyk:
- Pick up new manifests
- remove manifests that no longer exist
- Detect repo name change and update (add new, remove old)
- Detect deleted repos and log for review

**STOP NOW IF ANY OF THE FOLLOWING ARE TRUE**
- You have .NET projects, re-import will break projects (PR status checks) due to target framework
- If monitoring non-default branches
- Using a brokered Github.com Integration
- Using an SCM other than Github.com

### Usage
```
usage: snyk-scm-refresh.py [-h] [--org-id=ORG_ID] [--project-id=PROJECT_ID]
                        [--dry-run]

optional arguments:
  -h, --help            show this help message and exit
  --org-id ORG_ID       The Snyk Organisation Id. If omitted, process all orgs
                        the Snyk user has access to.
  --project-id PROJECT_ID
                        The Snyk Project Id. if omitted, process all projects.
  --dry-run             Simulate processing of the script without making
                        changes to Snyk
```

Each run generates a set of output files:
  - _potential-repo-deletes.csv
     - repo no longer exists
  - _stale-manifests-deleted.csv
     - monitored manifest files no longer exists
  - _renamed-manifests-deleted.csv
     - manifests of renamed repos that were removed
  - _renamed-manifests-pending.csv
     - manifests of renamed repos that were not removed. Only when the import of the repo under the new name is copmpleted are the old ones removed.
  - _completed-project-imports.csv
     - manifests that were imported during this job run

## Dependencies
pysnyk, PyGithub, requests

```
pip install -r  requirements.txt
```
or
```
python3 -m pip install -r requirements.txt
```
## Environment
```
export SNYK_TOKEN=<snyk-token>
export GITHUB_TOKEN=<github-token>
```

## Instructions
Make sure to use a user *API Token* that has acess to the Snyk Orgs you need to process with the script.  A service account will *not* work for GitHub, which is the only SCM currently supported at this time.

Ensure that your GITHUB_TOKEN has access to the repos contained in the Snyk Orgs in scope
If unsure, try one org at a time with --org-id


**Recommended:** This tool will delete projects from Snyk that are detected as stale or have since been renamed
  
Use the --dry-run option to verify the execution plan for the first run

  

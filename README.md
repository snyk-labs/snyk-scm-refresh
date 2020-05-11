# snyk-scm-refresh
[![Known Vulnerabilities](https://snyk.io/test/github/snyk-tech-services/snyk-scm-refresh/badge.svg)](https://snyk.io/test/github/snyk-tech-services/snyk-scm-refresh)

Keeps Snyk projects in sync with their associated Github repos

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

If any of the following are true, do not use this tool:
- If you have .NET projects, re-import will break projects (PR status checks) due to target framework.
- If monitoring non-default branches

If bringing in new Python project, the version needs to be set correctly in the Org

### Usage
```
usage: snyk-scm-refresh [-h] [--org-id ORG_ID] [--project-id PROJECT_ID]
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

Each run generates additional output files:
  - _potential-deletes.csv
  - _stale-manifests-deleted.csv
  - _renamed-manifests-deleted.csv
  - _renamed_manifests-pending.csv
  

## TODO
- additional tests

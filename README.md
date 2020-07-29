# snyk-scm-refresh
[![Known Vulnerabilities](https://snyk.io/test/github/snyk-tech-services/snyk-scm-refresh/badge.svg)](https://snyk.io/test/github/snyk-tech-services/snyk-scm-refresh)

Keeps Snyk projects in sync with their associated Github repos

For repos with at least 1 project already in Snyk:
- Detect new manifests
- Remove projects for manifests that no longer exist
- Update projects when a repo has been renamed 
- Detect deleted repos and log for review

**STOP NOW IF ANY OF THE FOLLOWING ARE TRUE**
- Monitoring non-default branches
- Using an SCM other than Github.com

## Usage
```
usage: snyk_scm_refresh.py [-h] [--org-id ORG_ID] [--repo-name REPO_NAME]
                           [--dry-run]

optional arguments:
  -h, --help            show this help message and exit
  --org-id ORG_ID       The Snyk Organisation Id found in Organization >
                        Settings. If omitted, process all orgs the Snyk user
                        has access to.
  --repo-name REPO_NAME
                        The full name of the repo to process (e.g.
                        githubuser/githubrepo). If omitted, process all repos
                        in the Snyk org.
  --dry-run             Simulate processing of the script without making
                        changes to Snyk
```



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
If unsure, try one org at a time with `--org-id`


**Recommended:** 
This tool will delete projects from Snyk that are detected as stale or have since been renamed
  
Use the `--dry-run` option to verify the execution plan for the first run

  Each run generates a set of output files:
| File Name           | Description |
| ------------------- | ----------- |
| snyk-scm-refresh.log | debug log output good for troubleshooting |
| _potential-repo-deletes.csv | repo no longer exists |
| _stale-manifests-deleted.csv | monitored manifest files no longer exists |
| _renamed-manifests-deleted.csv | manifests of renamed repos that were removed |
| _renamed-manifests-pending.csv | manifests of renamed repos that were not removed. Only when the import of the repo under the new name is copmpleted are the old ones removed. |
| _completed-project-imports.csv | manifests that were imported during this job run |
| _repos-skipped-on-error.csv | repos skipped due to import error |

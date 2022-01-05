# snyk-scm-refresh
[![Known Vulnerabilities](https://snyk.io/test/github/snyk-tech-services/snyk-scm-refresh/badge.svg)](https://snyk.io/test/github/snyk-tech-services/snyk-scm-refresh) [![circleci](https://circleci.com/gh/snyk-tech-services/snyk-scm-refresh.svg?style=svg)](https://circleci.com/gh/snyk-tech-services/snyk-scm-refresh)

Keeps Snyk projects in sync with their associated Github repos

For repos with at least 1 project already in Snyk:
- Detect and import new manifests
- Remove projects for manifests that no longer exist
- Update projects when a repo has been renamed 
- Detect and update default branch change (not renaming)
- Enable Snyk Code analysis for repos
- Detect deleted repos and log for review

**STOP NOW IF ANY OF THE FOLLOWING ARE TRUE**
- Monitoring non-default branches
- Using an SCM other than Github.com or Github Enterprise Server

## Usage
```
usage: snyk_scm_refresh.py [-h] [--org-id ORG_ID] [--repo-name REPO_NAME] [--sca {on,off}] 
       [--container {on,off}] [--iac {on,off}] [--code {on,off}] [--dry-run] [--debug]

optional arguments:
  -h, --help            show this help message and exit
  --org-id ORG_ID       The Snyk Organisation Id found in Organization > Settings. 
                        If omitted, process all orgs the Snyk user has access to.
  --repo-name REPO_NAME
                        The full name of the repo to process (e.g. githubuser/githubrepo). 
                        If omitted, process all repos in the Snyk org.
  --sca {on,off}        scan for SCA manifests (on by default)
  --container {on,off}  scan for container projects, e.g. Dockerfile (on by default)
  --iac {on,off}        scan for IAC manifests (experimental, off by default)
  --code {on,off}       create code analysis if not present (experimental, off by default)
  --dry-run             Simulate processing of the script without making changes to Snyk
  --debug               Write detailed debug data to snyk_scm_refresh.log for troubleshooting
```

### Sync with defaults
`./snyk_scm_refresh.py --org-id=12345`

### Sync SCA projects only
`./snyk_scm_refresh.py --org-id=12345 --container=off`

### Sync Container projects only
`./snyk_scm_refresh.py --org-id=12345 --sca=off --container=on`

### Enable Snyk Code analysis for repos
only: `./snyk_scm_refresh.py --org-id=12345 --sca=off --container=off --code=on` \
defaults + snyk code enable: `./snyk_scm_refresh.py --org-id=12345 --code=on`


## Dependencies
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
export GITHUB_ENTERPRISE_TOKEN=<github-enterprise-token>
export GITHUB_ENTERPRISE_HOST=<github-enterprise-host>
```
If GITHUB_TOKEN is set, your Github.com repos will processed

If GITHUB_ENTERPRISE_TOKEN and GITHUB_ENTERPRISE_HOST are BOTH set, your Github Enterprise Server repos will be processed

## Instructions
Make sure to use a user *API Token* that has acess to the Snyk Orgs you need to process with the script.  A service account will *not* work for GitHub, which is the only SCM currently supported at this time.

Ensure that your GITHUB_TOKEN or GITHUB_ENTERPRISE_TOKEN has access to the repos contained in the Snyk Orgs in scope
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
| _renamed-manifests-pending.csv | manifests of renamed repos that were not removed. Only when the import of the repo under the new name is completed are the old ones removed. |
| _completed-project-imports.csv | manifests that were imported during this job run |
| _updated-project-branches.csv | projects with updated default branch  |
| _update-project-branches-errors.csv | projects that had an error attempting to update default branch |
| _repos-skipped-on-error.csv | repos skipped due to import error |

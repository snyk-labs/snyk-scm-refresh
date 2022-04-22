# snyk-scm-refresh
[![Known Vulnerabilities](https://snyk.io/test/github/snyk-tech-services/snyk-scm-refresh/badge.svg)](https://snyk.io/test/github/snyk-tech-services/snyk-scm-refresh) [![circleci](https://circleci.com/gh/snyk-tech-services/snyk-scm-refresh.svg?style=svg)](https://circleci.com/gh/snyk-tech-services/snyk-scm-refresh)

<blockquote>
<g-emoji class="g-emoji" alias="warning" fallback-src="https://github.githubassets.com/images/icons/emoji/unicode/26a0.png">⚠️</g-emoji> <strong>WARNING:</strong>
Python 3.10 introduces breaking changes that are currently incompatible with this tool. You must use Python 3.7-3.9
</blockquote>
<br/>

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
                           [--container {on,off}] [--iac {on,off}] [--code {on,off}] [--dry-run]
                           [--skip-scm-validation] [--debug]

optional arguments:
  -h, --help            show this help message and exit
  --org-id ORG_ID       The Snyk Organisation Id found in Organization > Settings. If omitted,
                        process all orgs the Snyk user has access to.
  --repo-name REPO_NAME
                        The full name of the repo to process (e.g. githubuser/githubrepo). If
                        omitted, process all repos in the Snyk org.
  --sca {on,off}        scan for SCA manifests (on by default)
  --container {on,off}  scan for container projects, e.g. Dockerfile (on by default)
  --iac {on,off}        scan for IAC manifests (experimental, off by default)
  --code {on,off}       create code analysis if not present (experimental, off by default)
  --dry-run             Simulate processing of the script without making changes to Snyk
  --skip-scm-validation
                        Skip validation of the TLS certificate used by the SCM
  --audit-large-repos   only query github tree api to see if the response is truncated and 
                        log the result. These are the repos that would have be cloned via this tool
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
pip install -r requirements.txt
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

<blockquote>
:information_source:
If using the Snyk Github Enterprise Integration type for your Github.com repositories, then set GITHUB_ENTERPRISE_HOST=api.github.com
</blockquote>
<br/>

### Getting a GitHub token

1. In GitHub.com browse: https://github.com/settings/tokens/new. Or in GitHub Enterprise select your user icon (top-right), then 'Settings', then 'Developer settings', then 'Personal access tokens'.
2. Scopes - Public repos do not need a scope. If you want to scan private repos, then you'll need to enable this scope: `repo` (Full control of private repositories)

### Handling self-signed certificates
This tool uses the python requests library, therefore you can point [REQUESTS_CA_BUNDLE](https://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification) environment variable to the location of your cert bundle

`export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt`

If you are not able to validate the self-signed certificate, you may skip validation by providing the `--skip-scm-validation` option. 

## Instructions
Make sure to use a user *API Token* that has access to the Snyk Orgs you need to process with the script.  A service account will *not* work for GitHub, which is the only SCM currently supported at this time.

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

## Handling of large repositories
The primary method used by this tool to retrieve the GIT tree from each repository for the basis of comparison is via the Github API.  
For sufficiently large repositories, though, Github truncates the API response.  When a truncated Github response is detected when retrieving the GIT tree,
this tool will fall back on using the local `git` if available and configured to perform a shallow clone of the repository's default branch in order to build the tree.

It will use /tmp to perform the `git clone` and then capture the output of `git ls-tree -r`

When this situation occurs, you will see the following in the console:
```
Large repo detected, falling back to cloning. This may take a few minutes ...
```

![image](https://user-images.githubusercontent.com/59706011/163878251-e874b073-eab6-48c0-9bd3-ea995005e4a9.png)

The truncated GIT tree response is described [here](https://docs.github.com/en/rest/reference/git#get-a-tree).  The last [known limits](https://github.community/t/github-get-tree-api-limits-and-recursivity/1300/2) are: 100,000 files or 7 MB of response data, whichever is first.

### Auditing which repos are considered large
In order to detect which repositories in snyk are subject the tree truncation issue mentioned above, there is another available option `--audit-large-repos`.
This will only query the git tree via API and look for a truncated response, and then log the results to a file `snyk-scm-refresh_large-repos-audit-results.csv`

To find all the repos based on a Snyk org, use the `--org-id` parameter in conjunction with `--audit-large-repos`
Optionally you can also supply a repo name to check a single repo by also supplying the `--repo-name` filter.

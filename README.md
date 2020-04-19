# snyk-scm-refresh
## Dependencies
pysnyk, PyGithub, requests

```
pip install -r  requirements.txt
```
or
```
python3 -m pip install -r requirements.txt
```

## Instructions
Make sure to use a user *API Token* that has acess to the Snyk Orgs you need to process with the script.  A service account will *not* work for GitHub, which is the only SCM currently supported at this time.

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

## TODO
- error handling (do not delete old projects before i know i've successfully imported the new ones
- preserve enforced status checks at github if importing renamed projects
- tests

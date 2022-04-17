"""
data and methods for managing
snyk projects from the same repository
"""
import sys
import re
import snyk
import common
from app.gh_repo import (
    get_repo_manifests,
    passes_manifest_filter
)
import app

class SnykRepo():
    """ SnykRepo object """
    # pylint: disable=too-many-arguments
    def __init__(
            self,
            full_name: str,
            org_id: str,
            org_name: str,
            integration_id: str,
            origin: str,
            branch: str,
            snyk_projects: []
    ):
        self.full_name = full_name
        self.org_id = org_id
        self.org_name = org_name
        self.integration_id = integration_id
        self.origin = origin
        self.branch = branch
        self.snyk_projects = snyk_projects

    def __repr__(self):
        return (
            f"{self.full_name}" + "\n"
            f"{self.org_id}" + "\n"
            f"{self.org_name}" + "\n"
            f"{self.integration_id}" + "\n"
            f"{self.origin}" + "\n"
            f"{self.branch}" + "\n"
            f"{self.snyk_projects}")

    def __getitem__(self, item):
        return self.__dict__[item]

    def get_projects(self):
        """ return list of projects for this repo """
        return self.snyk_projects

    def has_snyk_code(self):
        """ returns true if snyk already has a
            snyk code project for this repo """
        has_snyk_code = False
        for snyk_project in self.snyk_projects:
            if snyk_project["type"] == "sast":
                has_snyk_code = True
                break
        return has_snyk_code

    def add_new_manifests(self, dry_run):
        """ find and import new projects """
        import_response = []
        files = []

        gh_repo_manifests = get_repo_manifests(self.full_name, self.origin, self.has_snyk_code())

        for gh_repo_manifest in gh_repo_manifests:
            #print(f"checking to import: {gh_repo_manifest}")
            if gh_repo_manifest not in {sp['manifest'] for sp in self.snyk_projects}:
                files.append(dict({"path": gh_repo_manifest}))

        # if there are files to add, then import them
        if not dry_run:
            if len(files) > 0:
                import_response = app.utils.snyk_helper.import_manifests(
                    self.org_id,
                    self.full_name,
                    self.integration_id,
                    files)
        else:
            for file in files:
                import_message = ""
                if re.match(common.MANIFEST_PATTERN_CODE, file["path"]):
                    import_message = "would trigger code analysis via"
                else:
                    import_message = "would import"

                app.utils.snyk_helper.app_print(self.org_name,
                                                self.full_name,
                                                f"{import_message}: {file['path']}")
        return import_response

    def delete_stale_manifests(self, dry_run):
        """ delete snyk projects for which the corresponding SCM file no longer exists """
        result = []
        gh_repo_manifests = get_repo_manifests(self.full_name, self.origin, True)
        for snyk_project in self.snyk_projects:
            # print(snyk_project["manifest"])
            if (snyk_project["type"] != "sast" and
                    passes_manifest_filter(snyk_project["manifest"]) and
                    snyk_project["manifest"] not in gh_repo_manifests):
                # delete project, append on success
                if not dry_run:
                    try:
                        app.utils.snyk_helper.delete_snyk_project(snyk_project["id"],
                                                                  snyk_project["org_id"])
                        result.append(snyk_project)
                    except snyk.errors.SnykNotFoundError:
                        print(f"    - Project {snyk_project['id']} not found" \
                            f" in org {snyk_project['org_id']}")
        return result

    def update_branch(self, new_branch_name, dry_run):
        """ update the branch for all snyk projects for this repo """
        result = []
        for (i, snyk_project) in enumerate(self.snyk_projects):
            if snyk_project["branch"] != new_branch_name:
                if not dry_run:
                    sys.stdout.write(f"\r  - {i+1}/{len(self.snyk_projects)}")
                    sys.stdout.flush()
                    try:
                        app.utils.snyk_helper.update_project_branch(snyk_project["id"],
                                                                    snyk_project["name"],
                                                                    snyk_project["org_id"],
                                                                    new_branch_name)
                    except snyk.errors.SnykNotFoundError:
                        print(f"    - Project {snyk_project['id']} not found" \
                            f" in org {snyk_project['org_id']}")

                    result.append(snyk_project)

        sys.stdout.write("\r")
        self.branch = new_branch_name
        return result

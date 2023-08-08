This guide aims to ease up the transition between working with the deprecated snyk-scm-refresh tool and the snyk-api-import tool.

# Some Differences
## Language
snyk-scm-refresh was written in `Python` whereas snyk-api-import is written in `Typescript`

snyk-scm-refresh was ran using either `Python` or a standalone executable whereas snyk-api-import can be run using `npm or yarn` or a standalone executable. Please refer to [Snyk's Public Documentation](https://docs.snyk.io/snyk-api-info/other-tools/tool-snyk-api-import#installation) for more information. 

# Migration

## Detecting and Importing New Manifests from a monitored repository
Use Snyk-API-Import tool's `import` command following the [Kicking off an Import Section](https://github.com/snyk-tech-services/snyk-api-import/blob/master/docs/import.md). The recommendation is to run this tool on a cronjob or on an event trigger to kick off the re-importing of repos into Snyk, which will detect and import the new manifests. 

Alternatively, use the Snyk-API-Import tool's `sync` command following the [Sync: detecting changes in monitored repos and updating Snyk projects Section](https://github.com/snyk-tech-services/snyk-api-import/blob/master/docs/sync.md). Any manifests that do not already exist in Snyk will be imported into Snyk using this `sync` command. (Note: by default, the sync command will only detect and sync changes in manifest files supported by Snyk Opensource. To sync files for other Snyk products, specify the appropriate Snyk product using the `--snykProduct` flag). 

### Expected Result 
The result will be the addition of the new manifest files within Snyk.

## Removing Projects for manifests that no longer exist within a monitored repository
Use the Snyk-API-Import tool's `sync` command following the [Sync: detecting changes in monitored repos and updating Snyk projects Section](https://github.com/snyk-tech-services/snyk-api-import/blob/master/docs/sync.md). Any manifests that no longer exist will be **deactivated** in Snyk and not **deleted**. Unlike Deletion, Deactivation will ensure that the historical data for that manifest file will remain in Snyk, whereas a Deletion will lead to permanent data loss for the deleted manifest file(s). (Note: by default, the sync command will only detect and sync changes in manifest files supported by Snyk Opensource. To sync files for other Snyk products, specify the appropriate Snyk product using the `--snykProduct` flag). 

### Expected Result
The result will be the deactivation of the removed manifest file(s) within Snyk. Note: You will have to delete the deactivated projects if you wish to completely remove them from Snyk, which will result in the permanent loss of data for these projects. 

## Detect and update manifest file name changes and/or movement within a monitored repository (Rename or moving a manifest file within a monitored repository)
Use the Snyk-API-Import tool's `sync` command following the [Sync: detecting changes in monitored repos and updating Snyk projects Section](https://github.com/snyk-tech-services/snyk-api-import/blob/master/docs/sync.md). If an imported repo's manifest file is re-named or moved, any manifest files previously imported will become broken projects in Snyk and therefore deactivated by sync command. However, the sync command will also properly re-import the repo with the appropriate repo name change along with a reimport of the files to properly follow the new repo name. 

### Expected Result
The result will be the deactivation of the projects created during initial import, but a re-import job will trigger, resulting in displaying the projects with the correct name/path. Note: You will have to delete any deactivated projects if you wish to completely remove them from Snyk, which will result in the permanent loss of data for these projects. 

## Detect and update default branch for a monitored repository (Rename or Switching to Another Branch)
Use the Snyk-API-Import tool's `sync` command following the [Sync: detecting changes in monitored repos and updating Snyk projects Section](https://github.com/snyk-tech-services/snyk-api-import/blob/master/docs/sync.md). If an imported repo's default branch is re-named, any manifest files previously imported will become broken projects in Snyk and therefore deactivated by sync command. However, the sync command will also properly re-import the repo with the appropriate repo name change along with a reimport of the files to properly follow the new repo name. 

### Expected Result
The result will be the deactivation of the projects created during initial import, but a re-import job will trigger, resulting in displaying the projects with the renamed default branch. 

## Detect whether a monitored repo has been archived
Use the Snyk-API-Import tool's `sync` command following the [Sync: detecting changes in monitored repos and updating Snyk projects Section](https://github.com/snyk-tech-services/snyk-api-import/blob/master/docs/sync.md). If an monitored repo is deactivated, the `sync` command will deactivate the projects within Snyk. 

### Expected Result
The result will be the deactivation of the projects within Snyk.

## Handling of Large Repositories
For sufficiently large repositories, though, Github truncates the API response. When a truncated Github response is detected, this tool will perform a shallow clone of the repository's default branch.

### Expected Result
The result will be the successful import of large repositories

## Detect deleted repos 
Today this is not supported by the snyk-api-import tool. Please refer to this [section](https://github.com/snyk-tech-services/snyk-api-import/blob/master/docs/sync.md#known-limitations) for understanding known limitations. 



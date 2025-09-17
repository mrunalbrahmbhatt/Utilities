# Utilities
Misc. utilities used or developed during development.


## 1. TDS to Unicorn
This script will crawl your given folder for .scproj files and generates the 95% of equivalent Unicorn single config file. Afterward, the user can customize the generated config according to their needs if something is not working.

### How to use:

1. .\TDStoUnicorn2.ps1 -ProjectName "ProjectName"  *> Project.Website.Serialization.config
2. Replace "ProjectName" in "Unicorn.ProjectName.Config" file content and name.

## 2. sync-workflows.sh
This script will download all repostiories one by one, and upload Microsoft Security DevOps Workflow in github 
### How to use [Bash command]:

1. Make sure [msdevopssec.yml](https://github.com/mrunalbrahmbhatt/Utilities/blob/master/.github/workflows/msdevopssec.yml) is in same folder as script.
2. $ ./sync-workflows.sh


### Disclaimer

This script is tested on internal projects only, thus feel free to modify to satisfy your needs. I'm not PowerShell/Shell script expert so please ignore my poor scripting. Also, I'm not favoring any tool here.

### Suggestion

Please share your suggestions or if you find the better way to do it @ it.mrunal@gmail.com.
Happy Sharing.



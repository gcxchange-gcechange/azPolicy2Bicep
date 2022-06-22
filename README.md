# azPolicy2Bicep
[![Build Status](https://dev.azure.com/gctools/gctools-outilsgc/_apis/build/status/gcxchange-gcechange.azPolicy2Bicep?branchName=main)](https://dev.azure.com/gctools/gctools-outilsgc/_build/latest?definitionId=10&branchName=main)

Tool for converting Azure policy dumps into bicep code
```
python3 azpolicy2bicep.py {path/to/definitions/dump.json} {path/to/initiatives/dump.json} {path/to/assignments/dump.json} {path/to/exemptions/dump.json} {output/directory}
```

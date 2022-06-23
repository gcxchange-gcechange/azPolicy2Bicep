# azPolicy2Bicep
[![Build Status](https://dev.azure.com/gctools/gctools-outilsgc/_apis/build/status/gcxchange-gcechange.azPolicy2Bicep?branchName=main)](https://dev.azure.com/gctools/gctools-outilsgc/_build/latest?definitionId=10&branchName=main)

Tool for converting Azure policy dumps into bicep code, currently assumes powershell style json dumps (most things under "Properties", capitalized keys, some values as enums / numbers instead of being spelled out)

```bash
python3 azpolicy2bicep.py {path/to/definitions/dump.json} {path/to/initiatives/dump.json} {path/to/assignments/dump.json} {path/to/exemptions/dump.json} {output/directory}
```


example export commands:
```powershell
Get-AzPolicyDefinition -Custom -ManagementGroupName '$MG_NAME' | ConvertTo-Json -Depth 9 > definitions.json
Get-AzPolicySetDefinition -Custom -ManagementGroupName '$MG_NAME' | ConvertTo-Json -Depth 9 > sets.json
Get-AzPolicyAssignment | ConvertTo-Json -Depth 9 > assignments.json
Get-AzPolicyExemption | ConvertTo-Json -Depth 9 > exemptions.json
```



param name string
param displayName string = name
param description string = ''

param policyAssignmentId string

@allowed([
  'Mitigated'
  'Waiver'
])
param exemptionCategory string = 'Waiver'

resource exemption 'Microsoft.Authorization/policyExemptions@2020-07-01-preview' = {
    name: name
    properties: {
        displayName: displayName
        description: description
        policyAssignmentId: policyAssignmentId
        exemptionCategory: exemptionCategory
    }
}

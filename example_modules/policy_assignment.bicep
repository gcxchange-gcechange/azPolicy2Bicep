targetScope = 'managementGroup'

param name string
param displayName string = name

@allowed([
  'Default'
  'DoNotEnforce'
])
@description('Policy assignment enforcement mode.')
param enforcementMode string = 'DoNotEnforce'

param parameters object = {}
param policyDefinitionId string

@allowed([
  'SystemAssigned'
  'None'
])
param identity string = 'SystemAssigned'

param nonComplianceMessages array = []
param roleDefinitionIds array = []


resource assignment 'Microsoft.Authorization/policyAssignments@2022-06-01' = {
  name: name
  properties: {
    displayName: displayName
    policyDefinitionId: policyDefinitionId
    parameters: parameters
    enforcementMode: enforcementMode
    nonComplianceMessages: !empty(nonComplianceMessages) ? nonComplianceMessages : []
  }
  identity: identity == 'SystemAssigned' ? {
    type: identity
  } : null
}

resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for roleDefinitionId in roleDefinitionIds: if (!empty(roleDefinitionIds) && identity == 'SystemAssigned') {
  name: guid(managementGroup().name, roleDefinitionId, deployment().location, name)
  properties: {
    roleDefinitionId: roleDefinitionId
    principalId: assignment.identity.principalId
    principalType: 'ServicePrincipal'
  }
}]

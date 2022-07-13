
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


resource assignment 'Microsoft.Authorization/policyAssignments@2020-03-01' = {
  name: name
  properties: {
    displayName: displayName
    policyDefinitionId: policyDefinitionId
    parameters: parameters
    enforcementMode: enforcementMode
  }
}

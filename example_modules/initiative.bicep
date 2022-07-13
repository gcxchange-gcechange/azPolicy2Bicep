targetScope = 'managementGroup'

param name string
param displayName string = name

param policyDefinitionGroups array = []

param parameters object = {}
param policyDefinitions array


resource policySet 'Microsoft.Authorization/policySetDefinitions@2020-03-01' = {
    name: name
    properties: {
        displayName: displayName
        parameters: parameters
        policyDefinitionGroups: policyDefinitionGroups
        policyDefinitions: policyDefinitions
        policyType: 'Custom'
    }
}


output ID string = policySet.id

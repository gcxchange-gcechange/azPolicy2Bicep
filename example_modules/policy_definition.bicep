targetScope = 'managementGroup'

param name string
param description string = ''
param displayName string = name

param mode string = 'All'
param policyType string = 'Custom'

param parameters object = {}
param policyRule object


resource policy_definition 'Microsoft.Authorization/policyDefinitions@2021-06-01' = {
    name: name
    properties: {
        description: description
        displayName: displayName
        mode: mode
        parameters: parameters
        policyRule: policyRule
        policyType: policyType
    }
}


output ID string = policy_definition.id
output displayName string = policy_definition.properties.displayName

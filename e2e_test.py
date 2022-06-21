import unittest
from os import listdir, remove
from subprocess import run


class TestE2E(unittest.TestCase):

    def test(Self):
        test_input_files = {
            'definitions': 'e2e_test_files/definitions.json',
            'initiatives': 'e2e_test_files/initiatives.json',
            'assignments': 'e2e_test_files/assignments.json'
        }
        
        output_directory = 'e2e_test_output'
        expected_files_dict = {
            'definitions': ['Deny-VM-Creation.bicep', 'Deny-VM-Creation2.bicep'],
            'initiatives': ['custom.bicep', '095e4ed9-c835-4ab6-9439-b5644362a06c.bicep'],
            'assignments': ['location-resources.bicep', 'location-VMs.bicep', 'SecurityCenterBuiltIn.bicep']
        }

        # clean up test dir for this test
        if output_directory in listdir('./'):
            for subdirectory in listdir(output_directory):  
            # if there are files in here too, someone's been messing around there and needs to clean it up - might not want it automatically deleted
                for file in listdir(f"{output_directory}/{subdirectory}"):
                    remove(f"{output_directory}/{subdirectory}/{file}")

        run(['python3', 'azpolicy2bicep.py', test_input_files['definitions'], test_input_files['initiatives'], test_input_files['assignments'], output_directory])

        Self.maxDiff = None
        for dir, expected_files in expected_files_dict.items():
            Self.assertEqual(listdir(f"{output_directory}/{dir}").sort(), expected_files.sort())
            
            for bicep_file_name in listdir(f"{output_directory}/{dir}"):
                with open(f"{output_directory}/{dir}/{bicep_file_name}", 'r') as bicep_file:
                    Self.assertEqual(bicep_file.read(), Self._get_expected_file_string(dir, bicep_file_name))



    def _get_expected_file_string(Self, resource_type: str, file_name:str) -> str:
        expected = {
            'definitions': {
                'Deny-VM-Creation.bicep': """targetScope = 'managementGroup'

@allowed([
    'AuditIfNotExists'
    'Disabled'
])
param effectDefaultValue string = 'AuditIfNotExists'


var parameters = {
    effect: {
        type: 'String'
        allowedValues: [
            'AuditIfNotExists'
            'Disabled'
        ]
        defaultValue: effectDefaultValue
    }
}
var policyRule = {
    if: {
        allOf: [
            {
                field: 'type'
                equals: 'Microsoft.Compute/virtualMachines'
            }
        ]
    }
    then: {
        effect: '[parameters(\\'effect\\')]'
    }
}

resource policy_definition 'Microsoft.Authorization/policyDefinitions@2021-06-01' = {
    name: 'Deny-VM-Creation'
    properties: {
        description: 'Deny VM Creation - v2'
        displayName: 'Deny VM Creation test'
        mode: 'All'
        parameters: parameters
        policyRule: policyRule
        policyType: 'Custom'
    }
}


output ID string = policy_definition.id
output displayName string = policy_definition.properties.displayName
""",
                'Deny-VM-Creation2.bicep': """targetScope = 'managementGroup'


var parameters = {}
var policyRule = {
    if: {
        allOf: [
            {
                field: 'type'
                equals: 'Microsoft.Compute/virtualMachines'
            }
        ]
    }
    then: {
        effect: 'deny'
    }
}

resource policy_definition 'Microsoft.Authorization/policyDefinitions@2021-06-01' = {
    name: 'Deny-VM-Creation2'
    properties: {
        description: 'Deny VM Creation2 - v2'
        displayName: 'Deny VM Creation test2'
        mode: 'All'
        parameters: parameters
        policyRule: policyRule
        policyType: 'Custom'
    }
}


output ID string = policy_definition.id
output displayName string = policy_definition.properties.displayName
"""
            },
            'initiatives': {
                'custom.bicep': """targetScope = 'managementGroup'


var policyDefinitionGroups = [
    {
        name: 'Custom'
        displayName: 'Custom Controls'
    }
]
var parameters = {}
var policyDefinitions = [
    {
        policyDefinitionReferenceId: toLower(replace(Deny_VM_Creation.outputs.displayName, ' ', '-'))
        policyDefinitionId: Deny_VM_Creation.outputs.ID
        parameters: {}
        groupNames: [
            'Custom'
        ]
    }
    {
        policyDefinitionReferenceId: 'restrict-to-canada-central-and-canada-east-regions-for-resources'
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c'
        parameters: {
            listOfAllowedLocations: {
                value: [
                    'canadacentral'
                    'canadaeast'
                ]
            }
        }
        groupNames: [
            'Custom'
        ]
    }
]


resource policySet 'Microsoft.Authorization/policySetDefinitions@2020-03-01' = {
    name: 'custom'
    properties: {
        displayName: 'Custom Set'
        parameters: parameters
        policyDefinitionGroups: policyDefinitionGroups
        policyDefinitions: policyDefinitions
    }
}


// definitions from modules
module Deny_VM_Creation '../definitions/Deny-VM-Creation.bicep' = {
    name: 'Deny-VM-Creation'
}


output ID string = policySet.id
""",
                '095e4ed9-c835-4ab6-9439-b5644362a06c.bicep': """targetScope = 'managementGroup'

@allowed([
    'true'
    'false'
])
param IncludeArcMachinesDefaultValue string = 'false'


var policyDefinitionGroups = []
var parameters = {
    IncludeArcMachines: {
        type: 'String'
        allowedValues: [
            'true'
            'false'
        ]
        defaultValue: IncludeArcMachinesDefaultValue
    }
}
var policyDefinitions = [
    {
        policyDefinitionReferenceId: 'AINE_MaximumPasswordAge'
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/4ceb8dc2-559c-478b-a15b-733fbf1e3738'
        parameters: {
            IncludeArcMachines: {
                value: '[parameters(\\\'IncludeArcMachines\\\')]'
            }
        }
    }
    {
        policyDefinitionReferenceId: 'AINE_MinimumPasswordAge'
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/237b38db-ca4d-4259-9e47-7882441ca2c0'
        parameters: {
            IncludeArcMachines: {
                value: '[parameters(\\\'IncludeArcMachines\\\')]'
            }
        }
    }
    {
        policyDefinitionReferenceId: 'AINE_PasswordMustMeetComplexityRequirements'
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/bf16e0bb-31e1-4646-8202-60a235cc7e74'
        parameters: {
            IncludeArcMachines: {
                value: '[parameters(\\\'IncludeArcMachines\\\')]'
            }
        }
    }
    {
        policyDefinitionReferenceId: 'AINE_StorePasswordsUsingReversibleEncryption'
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/da0f98fe-a24b-4ad5-af69-bd0400233661'
        parameters: {
            IncludeArcMachines: {
                value: '[parameters(\\\'IncludeArcMachines\\\')]'
            }
        }
    }
    {
        policyDefinitionReferenceId: 'AINE_EnforcePasswordHistory'
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/5b054a0d-39e2-4d53-bea3-9734cad2c69b'
        parameters: {
            IncludeArcMachines: {
                value: '[parameters(\\\'IncludeArcMachines\\\')]'
            }
        }
    }
    {
        policyDefinitionReferenceId: 'AINE_MinimumPasswordLength'
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/a2d0e922-65d0-40c4-8f87-ea6da2d307a2'
        parameters: {
            IncludeArcMachines: {
                value: '[parameters(\\\'IncludeArcMachines\\\')]'
            }
        }
    }
    {
        policyDefinitionReferenceId: 'AINE_PasswordPolicy_msid110'
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/ea53dbee-c6c9-4f0e-9f9e-de0039b78023'
        parameters: {
            IncludeArcMachines: {
                value: '[parameters(\\\'IncludeArcMachines\\\')]'
            }
        }
    }
    {
        policyDefinitionReferenceId: 'AINE_PasswordPolicy_msid121'
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/e6955644-301c-44b5-a4c4-528577de6861'
        parameters: {
            IncludeArcMachines: {
                value: '[parameters(\\\'IncludeArcMachines\\\')]'
            }
        }
    }
    {
        policyDefinitionReferenceId: 'AINE_PasswordPolicy_msid232'
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/f6ec09a3-78bf-4f8f-99dc-6c77182d0f99'
        parameters: {
            IncludeArcMachines: {
                value: '[parameters(\\\'IncludeArcMachines\\\')]'
            }
        }
    }
]


resource policySet 'Microsoft.Authorization/policySetDefinitions@2020-03-01' = {
    name: '095e4ed9-c835-4ab6-9439-b5644362a06c'
    properties: {
        displayName: 'Audit machines with insecure password security settings'
        parameters: parameters
        policyDefinitionGroups: policyDefinitionGroups
        policyDefinitions: policyDefinitions
    }
}


// definitions from modules



output ID string = policySet.id
"""
            },
            'assignments': {
                'location-resources.bicep': """targetScope = 'managementGroup'


@allowed([
  'Default'
  'DoNotEnforce'
])
@description('Policy assignment enforcement mode.')
param enforcementMode string = 'DoNotEnforce'

param listOfAllowedLocations array = [
    'canadacentral'
    'canadaeast'
]


var parameters = {
    listOfAllowedLocations: {
        value: listOfAllowedLocations
    }
}

resource assignment 'Microsoft.Authorization/policyAssignments@2020-03-01' = {
  name: 'location-resources'
  properties: {
    displayName: 'Restrict to Canada Central and Canada East regions for Resources'
    policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c'
    parameters: parameters
    enforcementMode: enforcementMode
  }
}
""",
                'location-VMs.bicep': """targetScope = 'managementGroup'


@allowed([
  'Default'
  'DoNotEnforce'
])
@description('Policy assignment enforcement mode.')
param enforcementMode string = 'DoNotEnforce'


var parameters = {}

resource assignment 'Microsoft.Authorization/policyAssignments@2020-03-01' = {
  name: 'location-VMs'
  properties: {
    displayName: 'Custom set'
    policyDefinitionId: '/subscriptions/test-123/providers/Microsoft.Authorization/policySetDefinitions/custom'
    parameters: parameters
    enforcementMode: enforcementMode
  }
}
""",
                'SecurityCenterBuiltIn.bicep': """targetScope = 'managementGroup'


@allowed([
  'Default'
  'DoNotEnforce'
])
@description('Policy assignment enforcement mode.')
param enforcementMode string = 'Default'


var parameters = {}

resource assignment 'Microsoft.Authorization/policyAssignments@2020-03-01' = {
  name: 'SecurityCenterBuiltIn'
  properties: {
    displayName: 'ASC Default (subscription: test-123)'
    policyDefinitionId: '/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8'
    parameters: parameters
    enforcementMode: enforcementMode
  }
}
"""
            }
        }
        return expected[resource_type][file_name]
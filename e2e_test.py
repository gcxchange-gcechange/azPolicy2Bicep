import unittest
from os import listdir, remove
from subprocess import run


class TestE2E(unittest.TestCase):

    def test(Self):
        test_input_files = {
            'definitions': 'e2e_test_files/definitions.json',
            'initiatives': 'e2e_test_files/initiatives.json',
            'assignments': 'e2e_test_files/assignments.json',
            'exemptions': 'e2e_test_files/exemptions.json'
        }
        
        output_directory = 'e2e_test_output'
        expected_files_dict = {
            'definitions': ['Deny VM Creation test.bicep', 'Deny VM Creation test2.bicep'],
            'initiatives': ['Custom Set.bicep', 'Audit machines with insecure password security settings.bicep'],
            'assignments': ['Restrict to Canada Central and Canada East regions for Resources.bicep', 'Custom set.bicep', 'ASC Default (subscription: test-123).bicep'],
            'exemptions':  ['a test exemption.bicep']
        }

        # clean up test dir for this test
        if output_directory in listdir('./'):
            for subdirectory in listdir(output_directory):  
            # if there are files in here too, someone's been messing around there and needs to clean it up - might not want it automatically deleted
                for file in listdir(f"{output_directory}/{subdirectory}"):
                    remove(f"{output_directory}/{subdirectory}/{file}")

        run(['python3', 'azpolicy2bicep.py', test_input_files['definitions'], test_input_files['initiatives'], test_input_files['assignments'], test_input_files['exemptions'], output_directory])

        Self.maxDiff = None
        for dir, expected_files in expected_files_dict.items():

            expected_files.sort()
            files_list = listdir(f"{output_directory}/{dir}")
            files_list.sort()
            Self.assertEqual(files_list, expected_files)
            
            for bicep_file_name in listdir(f"{output_directory}/{dir}"):
                with open(f"{output_directory}/{dir}/{bicep_file_name}", 'r') as bicep_file:
                    Self.assertEqual(bicep_file.read(), Self._get_expected_file_string(dir, bicep_file_name))



    def _get_expected_file_string(Self, resource_type: str, file_name:str) -> str:
        expected = {
            'definitions': {
                'Deny VM Creation test.bicep': """targetScope = 'managementGroup'

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

module policy_definition '../../example_modules/policy_definition.bicep' = {
    name: 'Definition-Deny_VM_Creation_test'
    params: {
        name: 'Deny-VM-Creation'
        description: 'Deny VM Creation - v2'
        displayName: 'Deny VM Creation test'
        mode: 'All'
        parameters: parameters
        policyRule: policyRule
        policyType: 'Custom'
    }
}


output ID string = policy_definition.outputs.ID
output displayName string = policy_definition.outputs.displayName
""",
                'Deny VM Creation test2.bicep': """targetScope = 'managementGroup'


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

module policy_definition '../../example_modules/policy_definition.bicep' = {
    name: 'Definition-Deny_VM_Creation_test2'
    params: {
        name: 'Deny-VM-Creation2'
        description: 'Deny VM Creation2 - v2'
        displayName: 'Deny VM Creation test2'
        mode: 'All'
        parameters: parameters
        policyRule: policyRule
        policyType: 'Custom'
    }
}


output ID string = policy_definition.outputs.ID
output displayName string = policy_definition.outputs.displayName
"""
            },
            'initiatives': {
                'Custom Set.bicep': """targetScope = 'managementGroup'


var policyDefinitionGroups = [
    {
        name: 'Custom'
        displayName: 'Custom Controls'
    }
]
var parameters = {}
var policyDefinitions = [
    {
        policyDefinitionReferenceId: toLower(replace(module_Deny_VM_Creation_test.outputs.displayName, ' ', '-'))
        policyDefinitionId: module_Deny_VM_Creation_test.outputs.ID
        parameters: {}
        groupNames: [
            'Custom'
        ]
    }
    {
        policyDefinitionReferenceId: toLower(replace(module_Deny_VM_Creation_test2.outputs.displayName, ' ', '-'))
        policyDefinitionId: module_Deny_VM_Creation_test2.outputs.ID
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


module policySet '../../example_modules/initiative.bicep' = {
    name: 'Initiative-Custom_Set'
    params: {
        name: 'custom'
        displayName: 'Custom Set'
        parameters: parameters
        policyDefinitionGroups: policyDefinitionGroups
        policyDefinitions: policyDefinitions
    }
}


// definitions from modules
module module_Deny_VM_Creation_test '../definitions/Deny VM Creation test.bicep' = {
    name: 'Deny VM Creation test'
}
module module_Deny_VM_Creation_test2 '../definitions/Deny VM Creation test2.bicep' = {
    name: 'Deny VM Creation test2'
}


output ID string = policySet.outputs.ID
""",
                'Audit machines with insecure password security settings.bicep': """targetScope = 'managementGroup'

@allowed([
    'true'
    'false'
])
param IncludeArcMachines_123DefaultValue string = 'false'


var policyDefinitionGroups = []
var parameters = {
    'IncludeArcMachines-123': {
        type: 'String'
        allowedValues: [
            'true'
            'false'
        ]
        defaultValue: IncludeArcMachines_123DefaultValue
    }
}
var policyDefinitions = [
    {
        policyDefinitionReferenceId: 'AINE_MaximumPasswordAge'
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/4ceb8dc2-559c-478b-a15b-733fbf1e3738'
        parameters: {
            IncludeArcMachines: {
                value: '[parameters(\\\'IncludeArcMachines-123\\\')]'
            }
        }
    }
    {
        policyDefinitionReferenceId: 'AINE_MinimumPasswordAge'
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/237b38db-ca4d-4259-9e47-7882441ca2c0'
        parameters: {
            IncludeArcMachines: {
                value: '[parameters(\\\'IncludeArcMachines-123\\\')]'
            }
        }
    }
    {
        policyDefinitionReferenceId: 'AINE_PasswordMustMeetComplexityRequirements'
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/bf16e0bb-31e1-4646-8202-60a235cc7e74'
        parameters: {
            IncludeArcMachines: {
                value: '[parameters(\\\'IncludeArcMachines-123\\\')]'
            }
        }
    }
    {
        policyDefinitionReferenceId: 'AINE_StorePasswordsUsingReversibleEncryption'
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/da0f98fe-a24b-4ad5-af69-bd0400233661'
        parameters: {
            IncludeArcMachines: {
                value: '[parameters(\\\'IncludeArcMachines-123\\\')]'
            }
        }
    }
    {
        policyDefinitionReferenceId: 'AINE_EnforcePasswordHistory'
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/5b054a0d-39e2-4d53-bea3-9734cad2c69b'
        parameters: {
            IncludeArcMachines: {
                value: '[parameters(\\\'IncludeArcMachines-123\\\')]'
            }
        }
    }
    {
        policyDefinitionReferenceId: 'AINE_MinimumPasswordLength'
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/a2d0e922-65d0-40c4-8f87-ea6da2d307a2'
        parameters: {
            IncludeArcMachines: {
                value: '[parameters(\\\'IncludeArcMachines-123\\\')]'
            }
        }
    }
    {
        policyDefinitionReferenceId: 'AINE_PasswordPolicy_msid110'
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/ea53dbee-c6c9-4f0e-9f9e-de0039b78023'
        parameters: {
            IncludeArcMachines: {
                value: '[parameters(\\\'IncludeArcMachines-123\\\')]'
            }
        }
    }
    {
        policyDefinitionReferenceId: 'AINE_PasswordPolicy_msid121'
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/e6955644-301c-44b5-a4c4-528577de6861'
        parameters: {
            IncludeArcMachines: {
                value: '[parameters(\\\'IncludeArcMachines-123\\\')]'
            }
        }
    }
    {
        policyDefinitionReferenceId: 'AINE_PasswordPolicy_msid232'
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/f6ec09a3-78bf-4f8f-99dc-6c77182d0f99'
        parameters: {
            IncludeArcMachines: {
                value: '[parameters(\\\'IncludeArcMachines-123\\\')]'
            }
        }
    }
]


module policySet '../../example_modules/initiative.bicep' = {
    name: 'Initiative-Audit_machines_with_insecure_password_security_settings'
    params: {
        name: '095e4ed9-c835-4ab6-9439-b5644362a06c'
        displayName: 'Audit machines with insecure password security settings'
        parameters: parameters
        policyDefinitionGroups: policyDefinitionGroups
        policyDefinitions: policyDefinitions
    }
}


// definitions from modules



output ID string = policySet.outputs.ID
"""
            },
            'assignments': {
                'Restrict to Canada Central and Canada East regions for Resources.bicep': """targetScope = 'managementGroup'


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

module assignment '../../example_modules/policy_assignment.bicep' = {
  name: 'Assignment-Restrict_to_Canada_Central_and_Canada_East_regions_for_Resources'
  params: {
    name: 'location-resources'
    displayName: 'Restrict to Canada Central and Canada East regions for Resources'
    policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c'
    parameters: parameters
    enforcementMode: enforcementMode
  }
}
""",
                'Custom set.bicep': """targetScope = 'managementGroup'


@allowed([
  'Default'
  'DoNotEnforce'
])
@description('Policy assignment enforcement mode.')
param enforcementMode string = 'DoNotEnforce'


var parameters = {}

module assignment '../../example_modules/policy_assignment.bicep' = {
  name: 'Assignment-Custom_set'
  params: {
    name: 'location-VMs'
    displayName: 'Custom set'
    policyDefinitionId: policy.outputs.ID
    parameters: parameters
    enforcementMode: enforcementMode
  }
}

module policy '../initiatives/Custom Set.bicep' = {
    name: 'Custom Set'
}
""",
                'ASC Default (subscription: test-123).bicep': """targetScope = 'managementGroup'


@allowed([
  'Default'
  'DoNotEnforce'
])
@description('Policy assignment enforcement mode.')
param enforcementMode string = 'Default'


var parameters = {}

module assignment '../../example_modules/policy_assignment.bicep' = {
  name: 'Assignment-ASC_Default__subscription__test_123_'
  params: {
    name: 'SecurityCenterBuiltIn'
    displayName: 'ASC Default (subscription: test-123)'
    policyDefinitionId: '/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8'
    parameters: parameters
    enforcementMode: enforcementMode
  }
}
"""
            },
            'exemptions': {
                'a test exemption.bicep': """


module exemption '../../example_modules/policy_exemption.bicep' = {
    name: 'Exemption-a_test_exemption'
    params: {
        name: 'testexemp'
        displayName: 'a test exemption'
        description: ''
        policyAssignmentId: '/subscriptions/test-123/providers/Microsoft.Authorization/policyAssignments/location-VMs'
        exemptionCategory: 'Waiver'
    }
}
"""
            },
        }
        return expected[resource_type][file_name]
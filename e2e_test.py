import unittest
from os import listdir, remove
from subprocess import run


class TestE2E(unittest.TestCase):

    def test(Self):
        test_input_files = {
            'definitions': 'e2e_test_files/definitions.json'
        }
        
        output_directory = 'e2e_test_output'
        expected_files_dict = {
            'definitions': ['Deny-VM-Creation.bicep', 'Deny-VM-Creation2.bicep']
        }

        # clean up test dir for this test
        if output_directory in listdir('./'):
            for subdirectory in listdir(output_directory):  
            # if there are files in here too, someone's been messing around there and needs to clean it up - might not want it automatically deleted
                for file in listdir(f"{output_directory}/{subdirectory}"):
                    remove(f"{output_directory}/{subdirectory}/{file}")

        run(['python3', 'azpolicy2bicep.py', test_input_files['definitions'], output_directory])

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
            }
        }
        return expected[resource_type][file_name]
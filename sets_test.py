import unittest
import json
from os import listdir, remove

from azpolicy2bicep import generate_bicep_policy_set, process_policy_sets


class TestPolicyPolicySets(unittest.TestCase):

    def test_generate_bicep_policy_set(Self):
        test_reference_dict = {
            'Deny-VM-Creation': {
                'DisplayName': 'deny vm creation 2.7 test'
            }
        }
        test_policy_set_json = """{
  "Name": "custom",
  "ResourceId": "/subscriptions/123-soasdffpoasifu/providers/Microsoft.Authorization/policySetDefinitions/custom",
  "ResourceName": "custom",
  "ResourceType": "Microsoft.Authorization/policySetDefinitions",
  "SubscriptionId": "123-soasdffpoasifu",
  "PolicySetDefinitionId": "/subscriptions/123-soasdffpoasifu/providers/Microsoft.Authorization/policySetDefinitions/custom",
  "Properties": {
    "Description": null,
    "DisplayName": "Custom Set",
    "Metadata": {
      "createdBy": null,
      "createdOn": null,
      "updatedBy": null,
      "updatedOn": null
    },
    "Parameters": null,
    "PolicyDefinitionGroups": [
      {
        "name": "Custom",
        "displayName": "Custom Controls"
      }
    ],
    "PolicyDefinitions": [
      {
        "policyDefinitionReferenceId": "deny-vm-creation-test",
        "policyDefinitionId": "/subscriptions/123-soasdffpoasifu/providers/Microsoft.Authorization/policyDefinitions/Deny-VM-Creation",
        "parameters": {},
        "groupNames": [
          "Custom"
        ]
      },
      {
        "policyDefinitionReferenceId": "restrict-to-canada-central-and-canada-east-regions-for-resources",
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c",
        "parameters": {
          "listOfAllowedLocations": {
            "value": [
              "canadacentral",
              "canadaeast"
            ]
          }
        },
        "groupNames": [
          "Custom"
        ]
      }
    ],
    "PolicyType": 1
  }
}
"""
        expected_output = """targetScope = 'managementGroup'


var policyDefinitionGroups = [
    {
        name: 'Custom'
        displayName: 'Custom Controls'
    }
]
var parameters = {}
var policyDefinitions = [
    {
        policyDefinitionReferenceId: toLower(replace(module_deny_vm_creation_2_7_test.outputs.displayName, ' ', '-'))
        policyDefinitionId: module_deny_vm_creation_2_7_test.outputs.ID
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
    name: 'Initiative: Custom Set'
    params: {
        name: 'custom'
        displayName: 'Custom Set'
        parameters: parameters
        policyDefinitionGroups: policyDefinitionGroups
        policyDefinitions: policyDefinitions
    }
}


// definitions from modules
module module_deny_vm_creation_2_7_test '../definitions/deny vm creation 2.7 test.bicep' = {
    name: 'deny vm creation 2.7 test'
}


output ID string = policySet.outputs.ID
"""
        Self.maxDiff = None
        Self.assertEqual( generate_bicep_policy_set(json.loads(test_policy_set_json), test_reference_dict), expected_output )


    def test_write_set_files(Self):
        test_definitions_dump = """[
  {
    "Name": "Deny-VM-Creation",
    "ResourceId": "/subscriptions/123456-aasfoidj/providers/Microsoft.Authorization/policyDefinitions/Deny-VM-Creation",
    "ResourceName": "Deny-VM-Creation",
    "ResourceType": "Microsoft.Authorization/policyDefinitions",
    "SubscriptionId": "123456-aasfoidj",
    "Properties": {
      "Description": "Deny VM Creation - v2",
      "DisplayName": "Deny VM Creation test"
    }
    }
]
        """
        test_sets_dump = """[
{
    "Name": "06122b01-688c-42a8-af2e-fa97dd39aa3b",
    "ResourceId": "/providers/Microsoft.Authorization/policySetDefinitions/06122b01-688c-42a8-af2e-fa97dd39aa3b",
    "ResourceName": "06122b01-688c-42a8-af2e-fa97dd39aa3b",
    "ResourceType": "Microsoft.Authorization/policySetDefinitions",
    "SubscriptionId": null,
    "PolicySetDefinitionId": "/providers/Microsoft.Authorization/policySetDefinitions/06122b01-688c-42a8-af2e-fa97dd39aa3b",
    "Properties": {
      "Description": "This initiative deploys the policy requirements and audits Windows virtual machines in which the Administrators group does not contain only the specified members. For more information on Guest Configuration policies, please visit https://aka.ms/gcpol",
      "DisplayName": "[Deprecated]: Audit Windows VMs in which the Administrators group does not contain only the specified members",
      "Metadata": {
        "version": "1.0.0-deprecated",
        "category": "Guest Configuration",
        "deprecated": true
      },
      "Parameters": {
        "Members": {
          "type": "String",
          "metadata": {
            "displayName": "Members",
            "description": "A semicolon-separated list of all the expected members of the Administrators local group. Ex: Administrator; myUser1; myUser2"
          }
        }
      },
      "PolicyDefinitionGroups": null,
      "PolicyDefinitions": [
        {
          "policyDefinitionReferenceId": "Deploy_AdministratorsGroupMembers",
          "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/b821191b-3a12-44bc-9c38-212138a29ff3",
          "parameters": {
            "Members": {
              "value": "[parameters('Members')]"
            }
          }
        },
        {
          "policyDefinitionReferenceId": "Audit_AdministratorsGroupMembers",
          "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/cc7cda28-f867-4311-8497-a526129a8d19"
        }
      ],
      "PolicyType": 2
    }
  },
  {
    "Name": "custom",
    "ResourceId": "/subscriptions/123-soasdffpoasifu/providers/Microsoft.Authorization/policySetDefinitions/custom",
    "ResourceName": "custom",
    "ResourceType": "Microsoft.Authorization/policySetDefinitions",
    "SubscriptionId": "123-soasdffpoasifu",
    "PolicySetDefinitionId": "/subscriptions/123-soasdffpoasifu/providers/Microsoft.Authorization/policySetDefinitions/custom",
    "Properties": {
      "Description": null,
      "DisplayName": "Custom Set",
      "Metadata": {
        "createdBy": null,
        "createdOn": null,
        "updatedBy": null,
        "updatedOn": null
      },
      "Parameters": null,
      "PolicyDefinitionGroups": [
        {
          "name": "Custom",
          "displayName": "Custom Controls"
        }
      ],
      "PolicyDefinitions": [
        {
          "policyDefinitionReferenceId": "deny-vm-creation-test",
          "policyDefinitionId": "/subscriptions/123-soasdffpoasifu/providers/Microsoft.Authorization/policyDefinitions/Deny-VM-Creation",
          "parameters": {},
          "groupNames": [
            "Custom"
          ]
        },
        {
          "policyDefinitionReferenceId": "restrict-to-canada-central-and-canada-east-regions-for-resources",
          "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c",
          "parameters": {
            "listOfAllowedLocations": {
              "value": [
                "canadacentral",
                "canadaeast"
              ]
            }
          },
          "groupNames": [
            "Custom"
          ]
        }
      ],
      "PolicyType": 1
    }
  }
]
"""
        expected_output_directory = 'testing_directory'
        expected_files_list = ['Custom Set.bicep', '[Deprecated]: Audit Windows VMs in which the Administrators group does not contain only the specified members.bicep']

        # clean up test dir for this test
        if expected_output_directory in listdir('./'):
            for file in listdir(expected_output_directory):
                remove(f"{expected_output_directory}/{file}")

        process_policy_sets(json.loads(test_sets_dump), json.loads(test_definitions_dump), expected_output_directory)

        files_list = listdir(expected_output_directory)
        files_list.sort()
        expected_files_list.sort()
        Self.assertEqual(files_list, expected_files_list)


if __name__ == '__main__':
    unittest.main()
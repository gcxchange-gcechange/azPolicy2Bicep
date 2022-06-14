import unittest
import json
from os import listdir, remove

from azpolicy2bicep import generate_bicep_policy_set


class TestPolicyPolicySets(unittest.TestCase):

    def test_generate_bicep_policy_set(Self):
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

param listOfAllowedLocations array = [
    'canadacentral'
    'canadaeast'
]


var policyDefinitionGroups = [
    {
        name: 'Custom'
        displayName: 'Custom Controls'
    }
]

var policyDefinitions = [
    {
        groupNames: [
            'Custom'
        ]
        policyDefinitionId: denyVMs.outputs.ID
        policyDefinitionReferenceId: toLower(replace(denyVMs.outputs.displayName, ' ', '-'))
        parameters: {}
    }
    {
        groupNames: [
            'Custom'
        ]
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c'
        policyDefinitionReferenceId: toLower(replace('Restrict to Canada Central and Canada East regions for Resources', ' ', '-'))
        parameters: {
            listOfAllowedLocations: {
                value: listOfAllowedLocations
            }
        }
    }
]


resource customPolicySet 'Microsoft.Authorization/policySetDefinitions@2020-03-01' = {
    name: 'custom'
    properties: {
        displayName: 'Custom Set'
        policyDefinitionGroups: policyDefinitionGroups
        policyDefinitions: policyDefinitions
    }
}


// definitions from modules
module denyVMs '../definitions/Deny-VM-Creation.bicep' = {
    name: 'denyVM'
}


output ID string = customPolicySet.id
"""
        Self.assertEqual( generate_bicep_policy_set(json.loads(test_policy_set_json)), expected_output )
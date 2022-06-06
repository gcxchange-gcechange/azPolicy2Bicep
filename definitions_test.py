import unittest
import json

from azpolicy2bicep import generate_bicep_definition


class TestPolicyDefinitions(unittest.TestCase):

    def test_generate_bicep_definition(Self):
        test_definition_json = """{
    "Name": "e765b5de-1225-4ba3-bd56-1ac6695af988",
    "ResourceId": "/providers/Microsoft.Authorization/policyDefinitions/e765b5de-1225-4ba3-bd56-1ac6695af988",
    "ResourceName": "e765b5de-1225-4ba3-bd56-1ac6695af988",
    "ResourceType": "Microsoft.Authorization/policyDefinitions",
    "SubscriptionId": null,
    "Properties": {
      "Description": "This policy enables you to restrict the locations your organization can create resource groups in. Use to enforce your geo-compliance requirements.",
      "DisplayName": "Allowed locations for resource groups",
      "Metadata": {
        "version": "1.0.0",
        "category": "General"
      },
      "Mode": "All",
      "Parameters": {
        "listOfAllowedLocations": {
          "type": "Array",
          "metadata": {
            "description": "The list of locations that resource groups can be created in.",
            "strongType": "location",
            "displayName": "Allowed locations"
          }
        }
      },
      "PolicyRule": {
        "if": {
          "allOf": [
            {
              "field": "type",
              "equals": "Microsoft.Resources/subscriptions/resourceGroups"
            },
            {
              "field": "location",
              "notIn": "[parameters('listOfAllowedLocations')]"
            }
          ]
        },
        "then": {
          "effect": "deny"
        }
      },
      "PolicyType": 2
    },
    "PolicyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/e765b5de-1225-4ba3-bd56-1ac6695af988"
  }"""
        expected_output = """targetScope = 'managementGroup'


var parameters = {
    listOfAllowedLocations: {
        type: 'Array'
    }
}
var policyRule = {
    if: {
        allOf: [
            {
                field: 'type'
                equals: 'Microsoft.Resources/subscriptions/resourceGroups'
            }
            {
                field: 'location'
                notIn: '[parameters(\\'listOfAllowedLocations\\')]'
            }
        ]
    }
    then: {
        effect: 'deny'
    }
}

resource policy_definition 'Microsoft.Authorization/policyDefinitions@2021-06-01' = {
    name: 'e765b5de-1225-4ba3-bd56-1ac6695af988'
    properties: {
        description: 'This policy enables you to restrict the locations your organization can create resource groups in. Use to enforce your geo-compliance requirements.'
        displayName: 'Allowed locations for resource groups'
        mode: 'All'
        parameters: parameters
        policyRule: policyRule
        policyType: 'BuiltIn'
    }
}


output ID string = policy_definition.id
output displayName string = policy_definition.properties.displayName
"""
        Self.assertEqual( generate_bicep_definition(json.loads(test_definition_json)), expected_output )

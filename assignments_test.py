import unittest
import json
from os import listdir, remove

from azpolicy2bicep import generate_bicep_policy_assignment


class TestPolicyPolicySets(unittest.TestCase):

    def test_generate_bicep_policy_assignment(Self):
        test_policy_set_json = """{
    "Identity": null,
    "Location": null,
    "Name": "location-resources",
    "ResourceId": "/subscriptions/testing-123/providers/Microsoft.Authorization/policyAssignments/location-resources",
    "ResourceName": "location-resources",
    "ResourceGroupName": null,
    "ResourceType": "Microsoft.Authorization/policyAssignments",
    "SubscriptionId": "testing-123",
    "Sku": null,
    "PolicyAssignmentId": "/subscriptions/testing-123/providers/Microsoft.Authorization/policyAssignments/location-resources",
    "Properties": {
      "Scope": "/subscriptions/testing-123",
      "NotScopes": null,
      "DisplayName": "Restrict to Canada Central and Canada East regions for Resources",
      "Description": null,
      "Metadata": {
        "createdBy": null,
        "createdOn": null,
        "updatedBy": null,
        "updatedOn": null
      },
      "EnforcementMode": 1,
      "PolicyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c",
      "Parameters": {
        "listOfAllowedLocations": {
          "value": [
            "canadacentral",
            "canadaeast"
          ]
        }
      },
      "NonComplianceMessages": null
    }
  }"""
        expected_output = """targetScope = 'managementGroup'


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
        value: [
            'canadacentral'
            'canadaeast'
        ]
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
"""
        Self.maxDiff = None
        Self.assertEqual( generate_bicep_policy_assignment(json.loads(test_policy_set_json)), expected_output )


if __name__ == '__main__':
    unittest.main()
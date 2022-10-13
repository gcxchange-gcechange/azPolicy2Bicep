import unittest
import json
from os import listdir, remove

from azpolicy2bicep import generate_bicep_policy_assignment, process_policy_assignments


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
        },
        "metricsEnabled-7f89b1eb-583c-429a-8828-af049802c1d9": {
          "value": false
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

param metricsEnabled_7f89b1eb_583c_429a_8828_af049802c1d9 bool = false


var parameters = {
    listOfAllowedLocations: {
        value: listOfAllowedLocations
    }
    'metricsEnabled-7f89b1eb-583c-429a-8828-af049802c1d9': {
        value: metricsEnabled_7f89b1eb_583c_429a_8828_af049802c1d9
    }
}

module assignment '../../example_modules/policy_assignment.bicep' = {
  name: 'Restrict to Canada Central and Canada East regions for Resources'
  params: {
    name: 'location-resources'
    displayName: 'Restrict to Canada Central and Canada East regions for Resources'
    policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c'
    parameters: parameters
    enforcementMode: enforcementMode
  }
}
"""
        Self.maxDiff = None
        Self.assertEqual( generate_bicep_policy_assignment(json.loads(test_policy_set_json)), expected_output )

    def test_generate_bicep_custom_policy_assignment(Self):
        test_policy_set_json = """{
        "Identity": null,
        "Location": null,
        "Name": "location-VMs",
        "ResourceId": "/providers/Microsoft.Management/managementGroups/test/providers/Microsoft.Authorization/policyAssignments/location-VMs",
        "ResourceName": "location-VMs",
        "ResourceGroupName": null,
        "ResourceType": "Microsoft.Authorization/policyAssignments",
        "SubscriptionId": "test-123",
        "Sku": null,
        "PolicyAssignmentId": "/providers/Microsoft.Management/managementGroups/test/providers/Microsoft.Authorization/policyAssignments/location-VMs",
        "Properties": {
          "Scope": "/providers/Microsoft.Management/managementGroups/test",
          "NotScopes": null,
          "DisplayName": "Custom set",
          "Description": null,
          "Metadata": {
            "createdBy": null,
            "createdOn": null,
            "updatedBy": null,
            "updatedOn": null
          },
          "EnforcementMode": 1,
          "PolicyDefinitionId": "/providers/Microsoft.Management/managementGroups/test/providers/Microsoft.Authorization/policySetDefinitions/custom",
          "Parameters": {},
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


var parameters = {}

module assignment '../../example_modules/policy_assignment.bicep' = {
  name: 'Custom set'
  params: {
    name: 'location-VMs'
    displayName: 'Custom set'
    policyDefinitionId: custom.outputs.ID
    parameters: parameters
    enforcementMode: enforcementMode
  }
}

module custom '../initiatives/custom.bicep' = {
    name: 'custom'
}
"""
        Self.assertEqual( generate_bicep_policy_assignment(json.loads(test_policy_set_json)), expected_output )

    def test_write_assignment_files(Self):
        test_assignments_dump = """[
  {
    "Identity": null,
    "Location": null,
    "Name": "location-VMs",
    "ResourceId": "/subscriptions/test-123/providers/Microsoft.Authorization/policyAssignments/location-VMs",
    "ResourceName": "location-VMs",
    "ResourceGroupName": null,
    "ResourceType": "Microsoft.Authorization/policyAssignments",
    "SubscriptionId": "test-123",
    "Sku": null,
    "PolicyAssignmentId": "/subscriptions/test-123/providers/Microsoft.Authorization/policyAssignments/location-VMs",
    "Properties": {
      "Scope": "/subscriptions/test-123",
      "NotScopes": null,
      "DisplayName": "Custom set",
      "Description": null,
      "Metadata": {
        "createdBy": null,
        "createdOn": null,
        "updatedBy": null,
        "updatedOn": null
      },
      "EnforcementMode": 1,
      "PolicyDefinitionId": "/subscriptions/test-123/providers/Microsoft.Authorization/policySetDefinitions/custom",
      "Parameters": {},
      "NonComplianceMessages": null
    }
  },
  {
    "Identity": null,
    "Location": null,
    "Name": "SecurityCenterBuiltIn",
    "ResourceId": "/subscriptions/test-123/providers/Microsoft.Authorization/policyAssignments/SecurityCenterBuiltIn",
    "ResourceName": "SecurityCenterBuiltIn",
    "ResourceGroupName": null,
    "ResourceType": "Microsoft.Authorization/policyAssignments",
    "SubscriptionId": "test-123",
    "Sku": null,
    "PolicyAssignmentId": "/subscriptions/test-123/providers/Microsoft.Authorization/policyAssignments/SecurityCenterBuiltIn",
    "Properties": {
      "Scope": "/subscriptions/test-123",
      "NotScopes": null,
      "DisplayName": "ASC Default (subscription: test-123)",
      "Description": "This is the default set of policies monitored by Azure Security Center. It was automatically assigned as part of onboarding to Security Center. The default assignment contains only audit policies. For more information please visit https://aka.ms/ascpolicies",
      "Metadata": {
        "assignedBy": "Security Center",
        "createdBy": null,
        "createdOn": null,
        "updatedBy": null,
        "updatedOn": null
      },
      "EnforcementMode": 0,
      "PolicyDefinitionId": "/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8",
      "Parameters": {},
      "NonComplianceMessages": null
    }
  }
]"""
        expected_output_directory = 'testing_directory'
        expected_files_list = ['Custom set.bicep', 'ASC Default (subscription: test-123).bicep']

        # clean up test dir for this test
        if expected_output_directory in listdir('./'):
            for file in listdir(expected_output_directory):
                remove(f"{expected_output_directory}/{file}")

        process_policy_assignments(json.loads(test_assignments_dump), expected_output_directory)

        files_list = listdir(expected_output_directory)
        files_list.sort()
        expected_files_list.sort()
        Self.assertEqual(files_list, expected_files_list)


if __name__ == '__main__':
    unittest.main()
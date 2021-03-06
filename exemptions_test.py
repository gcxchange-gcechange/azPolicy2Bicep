import unittest
import json
from os import listdir, remove

from azpolicy2bicep import generate_bicep_policy_exemption


class TestPolicyPolicySets(unittest.TestCase):

    def test_generate_bicep_policy_exemption(Self):
        test_policy_set_json = """{
  "Properties": {
    "PolicyAssignmentId": "/subscriptions/test-123/providers/Microsoft.Authorization/policyAssignments/location-VMs",
    "PolicyDefinitionReferenceIds": null,
    "ExemptionCategory": "Waiver",
    "DisplayName": "a test exemption",
    "Description": "test exemption 1",
    "ExpiresOn": null,
    "Metadata": null
  },
  "SystemData": null,
  "Name": "testexemp",
  "ResourceId": "/subscriptions/test-123/providers/Microsoft.Authorization/policyExemptions/testexemp",
  "ResourceName": "testexemp",
  "ResourceGroupName": null,
  "ResourceType": "Microsoft.Authorization/policyExemptions",
  "SubscriptionId": "test-123"
}"""
        expected_output = """


module exemption '../../example_modules/policy_exemption.bicep' = {
    name: 'testexemp'
    params: {
        name: 'testexemp'
        displayName: 'a test exemption'
        description: 'test exemption 1'
        policyAssignmentId: '/subscriptions/test-123/providers/Microsoft.Authorization/policyAssignments/location-VMs'
        exemptionCategory: 'Waiver'
    }
}
"""
        Self.assertEqual( generate_bicep_policy_exemption(json.loads(test_policy_set_json)), expected_output )


if __name__ == '__main__':
    unittest.main()
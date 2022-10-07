import unittest
import json
from os import listdir, remove

from azpolicy2bicep import generate_bicep_definition, process_policy_definitions


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

module policy_definition '../../example_modules/policy_definition.bicep' = {
    name: 'Allowed locations for resource groups'
    params: {
        name: 'e765b5de-1225-4ba3-bd56-1ac6695af988'
        description: 'This policy enables you to restrict the locations your organization can create resource groups in. Use to enforce your geo-compliance requirements.'
        displayName: 'Allowed locations for resource groups'
        mode: 'All'
        parameters: parameters
        policyRule: policyRule
        policyType: 'BuiltIn'
    }
}


output ID string = policy_definition.outputs.ID
output displayName string = policy_definition.outputs.displayName
"""
        Self.maxDiff = None
        Self.assertEqual( generate_bicep_definition(json.loads(test_definition_json)), expected_output )

    def test_generate_bicep_definition_with_multiple_parameters(Self):
        test_definition_json = """{
    "Name": "009259b0-12e8-42c9-94e7-7af86aa58d13",
    "ResourceId": "/providers/Microsoft.Authorization/policyDefinitions/009259b0-12e8-42c9-94e7-7af86aa58d13",
    "ResourceName": "009259b0-12e8-42c9-94e7-7af86aa58d13",
    "ResourceType": "Microsoft.Authorization/policyDefinitions",
    "SubscriptionId": null,
    "Properties": {
      "Description": "Configure VMSS created with Shared Image Gallery images to automatically install the Guest Attestation extension to allow Azure Security Center to proactively attest and monitor the boot integrity. Boot integrity is attested via Remote Attestation.",
      "DisplayName": "[Preview]: Configure VMSS created with Shared Image Gallery images to install the Guest Attestation extension",
      "Metadata": {
        "category": "Security Center",
        "version": "2.0.0-preview",
        "preview": true
      },
      "Mode": "Indexed",
      "Parameters": {
        "effect": {
          "type": "String",
          "metadata": {
            "displayName": "Effect",
            "description": "Enable or disable the execution of the policy"
          },
          "allowedValues": [
            "DeployIfNotExists",
            "Disabled"
          ],
          "defaultValue": "DeployIfNotExists"
        },
        "attestationEndpoint": {
          "type": "String",
          "metadata": {
            "displayName": "Guest attestation tenant URL",
            "description": "The Microsoft Azure Attestation (MAA) custom tenant URL."
          },
          "defaultValue": ""
        }
      },
      "PolicyRule": {
        "if": {
          "allOf": [
            {
              "field": "type",
              "equals": "Microsoft.Compute/virtualMachineScaleSets"
            },
            {
              "field": "Microsoft.Compute/virtualMachineScaleSets/virtualMachineProfile.securityProfile.securityType",
              "equals": "TrustedLaunch"
            },
            {
              "field": "Microsoft.Compute/virtualMachineScaleSets/virtualMachineProfile.securityProfile.uefiSettings",
              "exists": "true"
            },
            {
              "field": "Microsoft.Compute/virtualMachineScaleSets/virtualMachineProfile.securityProfile.uefiSettings.vTpmEnabled",
              "equals": "true"
            },
            {
              "field": "Microsoft.Compute/virtualMachineScaleSets/virtualMachineProfile.securityProfile.uefiSettings.secureBootEnabled",
              "equals": "true"
            },
            {
              "field": "Microsoft.Compute/imageid",
              "exists": "true"
            }
          ]
        },
        "then": {
          "effect": "[parameters('effect')]",
          "details": {
            "type": "Microsoft.Compute/virtualMachineScaleSets/extensions",
            "existenceCondition": {
              "allOf": [
                {
                  "field": "Microsoft.Compute/virtualMachineScaleSets/extensions/publisher",
                  "in": [
                    "Microsoft.Azure.Security.LinuxAttestation",
                    "Microsoft.Azure.Security.WindowsAttestation"
                  ]
                },
                {
                  "field": "Microsoft.Compute/virtualMachineScaleSets/extensions/type",
                  "equals": "GuestAttestation"
                },
                {
                  "field": "Microsoft.Compute/virtualMachineScaleSets/extensions/provisioningState",
                  "in": [
                    "Succeeded",
                    "Provisioning succeeded"
                  ]
                }
              ]
            },
            "roleDefinitionIds": [
              "/providers/microsoft.authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7",
              "/providers/microsoft.authorization/roleDefinitions/9980e02c-c2be-4d73-94e8-173b1dc7cf3c"
            ],
            "deployment": {
              "properties": {
                "mode": "incremental",
                "parameters": {
                  "vmName": {
                    "value": "[field('name')]"
                  },
                  "location": {
                    "value": "[field('location')]"
                  },
                  "imageId": {
                    "value": "[field('Microsoft.Compute/imageid')]"
                  },
                  "attestationEndpoint": {
                    "value": "[parameters('attestationEndpoint')]"
                  }
                },
                "template": {
                  "$schema": "http://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
                  "contentVersion": "1.0.0.0",
                  "parameters": {
                    "vmName": "@{type=string}",
                    "location": "@{type=string}",
                    "imageId": "@{type=string}",
                    "attestationEndpoint": "@{type=string}"
                  },
                  "variables": {
                    "extensionName": "GuestAttestation",
                    "extensionPublisherPrefix": "Microsoft.Azure.Security.",
                    "extensionPublisherSuffix": "Attestation",
                    "extensionVersion": "1.0",
                    "maaTenantName": "GuestAttestation",
                    "ascReportingEndpoint": ""
                  },
                  "resources": [
                    "@{type=Microsoft.Compute/virtualMachineScaleSets/extensions; apiVersion=2018-10-01; name=[concat(parameters('vmName'), '/', variables('extensionName'))]; location=[parameters('location')]; properties=}"
                  ]
                }
              }
            }
          }
        }
      },
      "PolicyType": 2
    },
    "PolicyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/009259b0-12e8-42c9-94e7-7af86aa58d13"
  }"""
        expected_output = """targetScope = 'managementGroup'

@allowed([
    'DeployIfNotExists'
    'Disabled'
])
param effectDefaultValue string = 'DeployIfNotExists'

param attestationEndpointDefaultValue string = ''


var parameters = {
    effect: {
        type: 'String'
        allowedValues: [
            'DeployIfNotExists'
            'Disabled'
        ]
        defaultValue: effectDefaultValue
    }
    attestationEndpoint: {
        type: 'String'
        defaultValue: attestationEndpointDefaultValue
    }
}
var policyRule = {
    if: {
        allOf: [
            {
                field: 'type'
                equals: 'Microsoft.Compute/virtualMachineScaleSets'
            }
            {
                field: 'Microsoft.Compute/virtualMachineScaleSets/virtualMachineProfile.securityProfile.securityType'
                equals: 'TrustedLaunch'
            }
            {
                field: 'Microsoft.Compute/virtualMachineScaleSets/virtualMachineProfile.securityProfile.uefiSettings'
                exists: 'true'
            }
            {
                field: 'Microsoft.Compute/virtualMachineScaleSets/virtualMachineProfile.securityProfile.uefiSettings.vTpmEnabled'
                equals: 'true'
            }
            {
                field: 'Microsoft.Compute/virtualMachineScaleSets/virtualMachineProfile.securityProfile.uefiSettings.secureBootEnabled'
                equals: 'true'
            }
            {
                field: 'Microsoft.Compute/imageid'
                exists: 'true'
            }
        ]
    }
    then: {
        effect: '[parameters(\\'effect\\')]'
        details: {
            type: 'Microsoft.Compute/virtualMachineScaleSets/extensions'
            existenceCondition: {
                allOf: [
                    {
                        field: 'Microsoft.Compute/virtualMachineScaleSets/extensions/publisher'
                        in: [
                            'Microsoft.Azure.Security.LinuxAttestation'
                            'Microsoft.Azure.Security.WindowsAttestation'
                        ]
                    }
                    {
                        field: 'Microsoft.Compute/virtualMachineScaleSets/extensions/type'
                        equals: 'GuestAttestation'
                    }
                    {
                        field: 'Microsoft.Compute/virtualMachineScaleSets/extensions/provisioningState'
                        in: [
                            'Succeeded'
                            'Provisioning succeeded'
                        ]
                    }
                ]
            }
            roleDefinitionIds: [
                '/providers/microsoft.authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7'
                '/providers/microsoft.authorization/roleDefinitions/9980e02c-c2be-4d73-94e8-173b1dc7cf3c'
            ]
            deployment: {
                properties: {
                    mode: 'incremental'
                    parameters: {
                        vmName: {
                            value: '[field(\\'name\\')]'
                        }
                        location: {
                            value: '[field(\\'location\\')]'
                        }
                        imageId: {
                            value: '[field(\\'Microsoft.Compute/imageid\\')]'
                        }
                        attestationEndpoint: {
                            value: '[parameters(\\'attestationEndpoint\\')]'
                        }
                    }
                    template: {
                        '$schema': 'http://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#'
                        contentVersion: '1.0.0.0'
                        parameters: {
                            vmName: '@{type=string}'
                            location: '@{type=string}'
                            imageId: '@{type=string}'
                            attestationEndpoint: '@{type=string}'
                        }
                        variables: {
                            extensionName: 'GuestAttestation'
                            extensionPublisherPrefix: 'Microsoft.Azure.Security.'
                            extensionPublisherSuffix: 'Attestation'
                            extensionVersion: '1.0'
                            maaTenantName: 'GuestAttestation'
                            ascReportingEndpoint: ''
                        }
                        resources: [
                            '@{type=Microsoft.Compute/virtualMachineScaleSets/extensions; apiVersion=2018-10-01; name=[concat(parameters(\\'vmName\\'), \\'/\\', variables(\\'extensionName\\'))]; location=[parameters(\\'location\\')]; properties=}'
                        ]
                    }
                }
            }
        }
    }
}

module policy_definition '../../example_modules/policy_definition.bicep' = {
    name: '[Preview]: Configure VMSS created with Shared Image Gallery images to install the Guest Attestation extension'
    params: {
        name: '009259b0-12e8-42c9-94e7-7af86aa58d13'
        description: 'Configure VMSS created with Shared Image Gallery images to automatically install the Guest Attestation extension to allow Azure Security Center to proactively attest and monitor the boot integrity. Boot integrity is attested via Remote Attestation.'
        displayName: '[Preview]: Configure VMSS created with Shared Image Gallery images to install the Guest Attestation extension'
        mode: 'Indexed'
        parameters: parameters
        policyRule: policyRule
        policyType: 'BuiltIn'
    }
}


output ID string = policy_definition.outputs.ID
output displayName string = policy_definition.outputs.displayName
"""
        Self.assertEqual( generate_bicep_definition(json.loads(test_definition_json)), expected_output )

### not quite an end-to-end test, mainly concerned with the files being created / written properly
    def test_write_definition_files(Self):
        test_definitions_dump = """[
  {
    "Name": "Deny-VM-Creation",
    "ResourceId": "/subscriptions/123456-aasfoidj/providers/Microsoft.Authorization/policyDefinitions/Deny-VM-Creation",
    "ResourceName": "Deny-VM-Creation",
    "ResourceType": "Microsoft.Authorization/policyDefinitions",
    "SubscriptionId": "123456-aasfoidj",
    "Properties": {
      "Description": "Deny VM Creation - v2",
      "DisplayName": "Deny VM Creation test",
      "Metadata": {
        "createdBy": null,
        "createdOn": null,
        "updatedBy": null,
        "updatedOn": null
      },
      "Mode": "All",
      "Parameters": {
        "effect": {
          "allowedValues": [
            "AuditIfNotExists",
            "Disabled"
          ],
          "defaultValue": "AuditIfNotExists",
          "metadata": {
            "additionalProperties": null,
            "assignPermissions": null,
            "description": "Enable or disable the execution of the policy",
            "displayName": "Effect",
            "strongType": null
          },
          "type": "String"
        }
      },
      "PolicyRule": {
        "if": {
          "allOf": [
            {
              "field": "type",
              "equals": "Microsoft.Compute/virtualMachines"
            }
          ]
        },
        "then": {
          "effect": "[parameters('effect')]"
        }
      },
      "PolicyType": 1
    },
    "PolicyDefinitionId": "/subscriptions/123456-aasfoidj/providers/Microsoft.Authorization/policyDefinitions/Deny-VM-Creation"
  },
  {
    "Name": "Deny-VM-Creation2",
    "ResourceId": "/subscriptions/123456-aasfoidj/providers/Microsoft.Authorization/policyDefinitions/Deny-VM-Creation2",
    "ResourceName": "Deny-VM-Creation2",
    "ResourceType": "Microsoft.Authorization/policyDefinitions",
    "SubscriptionId": "123456-aasfoidj",
    "Properties": {
      "Description": "Deny VM Creation2 - v2",
      "DisplayName": "Deny VM Creation test2",
      "Metadata": {
        "createdBy": null,
        "createdOn": null,
        "updatedBy": null,
        "updatedOn": null
      },
      "Mode": "All",
      "Parameters": {},
      "PolicyRule": {
        "if": {
          "allOf": [
            {
              "field": "type",
              "equals": "Microsoft.Compute/virtualMachines"
            }
          ]
        },
        "then": {
          "effect": "deny"
        }
      },
      "PolicyType": 1
    },
    "PolicyDefinitionId": "/subscriptions/123456-aasfoidj/providers/Microsoft.Authorization/policyDefinitions/Deny-VM-Creation2"
  }
]
"""
        expected_output_directory = 'testing_directory'
        expected_files_list = ['Deny-VM-Creation.bicep', 'Deny-VM-Creation2.bicep']

        # clean up test dir for this test
        if expected_output_directory in listdir('./'):
            for file in listdir(expected_output_directory):
                remove(f"{expected_output_directory}/{file}")

        process_policy_definitions(json.loads(test_definitions_dump), expected_output_directory)

        Self.assertEqual(listdir(expected_output_directory).sort(), expected_files_list.sort())


if __name__ == '__main__':
    unittest.main()
import unittest
import json

from helpers import translate_to_bicep, indent, indentString, detect_pwsh_dump, enumerate_duplicate_display_names, generate_reference_dict, specials_to_underscore

# need to be able to handle: 
#   string, array, object, boolean, integer, float, or datetime
class TestBicepTranslation(unittest.TestCase):

# string-like
    def test_translate_string(Self):
        testInput = "this test's string"
        expectedOutput = "'this test\\'s string'"
        Self.assertEqual( translate_to_bicep(testInput, "String"), expectedOutput )
        Self.assertEqual( translate_to_bicep(testInput), expectedOutput )

    def test_translate_datetime(Self):
        testInput = "2042-02-28T19:45:12.7085046Z"
        expectedOutput = "'2042-02-28T19:45:12.7085046Z'"
        Self.assertEqual( translate_to_bicep(testInput, "datetime"), expectedOutput )
        Self.assertEqual( translate_to_bicep(testInput), expectedOutput )

# bicep doesn't need these ones in quotes
    def test_translate_int(Self):
        testInput = 12
        expectedOutput = "12"
        Self.assertEqual( translate_to_bicep(testInput, "Int"), expectedOutput )
        Self.assertEqual( translate_to_bicep(testInput), expectedOutput )

    def test_translate_float(Self):
        testInput = 3.1415
        expectedOutput = "'3.1415'"
        Self.assertEqual( translate_to_bicep(testInput, "Float"), expectedOutput )
        Self.assertEqual( translate_to_bicep(testInput), expectedOutput )

    def test_translate_bool(Self):
        testInput = True
        expectedOutput = "true"
        Self.assertEqual( translate_to_bicep(testInput, "Bool"), expectedOutput )
        Self.assertEqual( translate_to_bicep(testInput), expectedOutput )

# Objects, Arrays, and everything put together
    def test_array(Self):
        testInput = [True, "test", 2.73]
        expectedOutput = """[
    true
    'test'
    '2.73'
]"""
        Self.assertEqual( translate_to_bicep(testInput, "Array"), expectedOutput )
        Self.assertEqual( translate_to_bicep(testInput), expectedOutput )

    def test_object(Self):
        testInput = {'foo': 'bar', 'test-123': 123}
        expectedOutput = """{
    foo: 'bar'
    'test-123': 123
}"""
        Self.assertEqual( translate_to_bicep(testInput, "Object"), expectedOutput )
        Self.assertEqual( translate_to_bicep(testInput), expectedOutput )

    def test_special_character_keys(Self):
        testInput = {"$foo": "bar#", '@test &123': 123, "space test": 321}
        expectedOutput = """{
    '$foo': 'bar#'
    '@test &123': 123
    'space test': 321
}"""
        Self.assertEqual( translate_to_bicep(testInput, "Object"), expectedOutput )
        Self.assertEqual( translate_to_bicep(testInput), expectedOutput )

    def test_translate_nested_object_with_arrays(Self):
        testInput = json.loads("""{
        "listOfAllowedLocations": {
          "value": [
            "canadacentral",
            "canadaeast"
          ]
        }
      }""")
        expectedOutput = """{
    listOfAllowedLocations: {
        value: [
            'canadacentral'
            'canadaeast'
        ]
    }
}"""
        Self.assertEqual( translate_to_bicep(testInput, "Object"), expectedOutput )
        Self.assertEqual( translate_to_bicep(testInput), expectedOutput )

    def test_empty_object_and_array(Self):
        testInput = json.loads("""{
    "listOfAllowedLocations": {
        "value": [],
        "another": {}
    }
}""")
        expectedOutput = """{
    listOfAllowedLocations: {
        value: []
        another: {}
    }
}"""
        Self.assertEqual( translate_to_bicep(testInput, "Object"), expectedOutput )
        Self.assertEqual( translate_to_bicep(testInput), expectedOutput )

    def test_template_output(Self):
        testInput = json.loads("""{
    "listOfAllowedLocations": {
        "value": [],
        "another": {}
    }
}""")
        testInput['listOfAllowedLocations']['value'] = "{test}"
        expectedOutput = """{{
    listOfAllowedLocations: {{
        value: {test}
        another: {{}}
    }}
}}"""
        Self.assertEqual( translate_to_bicep(testInput, "Object", template=['{test}']), expectedOutput )
        Self.assertEqual( translate_to_bicep(testInput, template=['{test}']), expectedOutput )

class TestIndent(unittest.TestCase):

    def test_3_level_indent(Self):
        indent_level = 3
        expected_output = "            "
        Self.assertEqual( indent(indent_level=indent_level), expected_output )

    def test_0_level_indent(Self):
        indent_level = 0
        expected_output = ""
        Self.assertEqual( indent(indent_level=indent_level), expected_output )

    def test_default_level_indent(Self):
        expected_output = "    "
        Self.assertEqual( indent(), expected_output )

    def test_default_indent_string(Self):
        test_input = "Hi! I'm a test string!"
        expected_output = "    Hi! I'm a test string!"
        Self.assertEqual( indentString(test_input), expected_output )

    def test_indent_bicep_array(Self):
        indent_level = 2
        test_input = """
[
    'test'
    123
]"""
        expected_output = """        
        [
            'test'
            123
        ]"""
        Self.assertEqual( indentString(test_input, indent_level=indent_level), expected_output )

    def test_detect_powershell_dump(Self):
        test_input = """{
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
  }"""
        expected_output = 1
        Self.assertEqual( detect_pwsh_dump(json.loads(test_input)), expected_output )

class TestDisplayNames(unittest.TestCase):

    def test_duplicate_display_names(Self):
        testInput = json.loads("""[
    {
        "Name": "123asdf",
        "Properties": {
            "Description": "Deny VM Creation2 - v2",
            "DisplayName": "Deny VM Creation test"
        }
    },
    {
        "Name": "12345asdf",
        "Properties": {
            "Description": "Deny VM Creation2 - v2",
            "DisplayName": "Deny VM Creation test"
        }
    }
]""")
        expectedOutput = json.loads("""[
    {
        "Name": "123asdf",
        "Properties": {
            "Description": "Deny VM Creation2 - v2",
            "DisplayName": "Deny VM Creation test"
        }
    },
    {
        "Name": "12345asdf",
        "Properties": {
            "Description": "Deny VM Creation2 - v2",
            "DisplayName": "Deny VM Creation test_2"
        }
    }
]""")
        Self.assertEqual( enumerate_duplicate_display_names(testInput), expectedOutput )


    def test_generate_reference_dict(Self):
        testInput = json.loads("""[
    {
        "Name": "123asdf",
        "Properties": {
            "Description": "Deny VM Creation2 - v2",
            "DisplayName": "Deny VM Creation test"
        }
    },
    {
        "Name": "12345asdf",
        "Properties": {
            "Description": "Deny VM Creation2 - v2",
            "DisplayName": "Deny VM Creation"
        }
    }
]""")
        expectedOutput = json.loads("""{
        "123asdf": {
            "DisplayName": "Deny VM Creation test"
        },
        "12345asdf": {
            "DisplayName": "Deny VM Creation"
        }
}""")
        Self.assertEqual( generate_reference_dict(testInput), expectedOutput )

    def test_specials_to_underscore(Self):
        testInput = "test! #1.4, -- foo / bar"
        expectedOutput = "test___1_4_____foo___bar"

        Self.assertEqual( specials_to_underscore(testInput), expectedOutput )

if __name__ == '__main__':
    unittest.main()
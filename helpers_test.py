import unittest
import json

from helpers import translate_to_bicep

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
        expectedOutput = "3.1415"
        Self.assertEqual( translate_to_bicep(testInput, "Float"), expectedOutput )
        Self.assertEqual( translate_to_bicep(testInput), expectedOutput )

    def test_translate_bool(Self):
        testInput = True
        expectedOutput = "True"
        Self.assertEqual( translate_to_bicep(testInput, "Bool"), expectedOutput )
        Self.assertEqual( translate_to_bicep(testInput), expectedOutput )

# Objects, Arrays, and everything put together
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








if __name__ == '__main__':
    unittest.main()
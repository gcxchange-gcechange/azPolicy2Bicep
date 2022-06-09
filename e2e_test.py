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

        result = run(['python3', 'azpolicy2bicep.py', test_input_files['definitions'], output_directory])

        for dir, expected_files in expected_files_dict.items():
            Self.assertEqual(listdir(f"{output_directory}/{dir}"), expected_files)
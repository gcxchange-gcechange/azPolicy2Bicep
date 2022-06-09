import json
from sys import argv
from pathlib import Path

from helpers import translate_to_bicep, indentString

def _load_json_dump(file_name: str) -> dict:
    json_dict = {}
    with open(file_name, 'r') as definitions_file:
        json_dict = json.load(definitions_file)
    return json_dict

def _write_bicep_file(file_path: str, file_contents: str) -> None:
    with open(file_path, 'w') as bicep_file:
        bicep_file.write(file_contents)
    return

def _translate_definition(az_dump_dict: dict) -> dict:
    bicep_keys = ['Description', 'DisplayName', 'Mode', 'PolicyRule']
    bicep_dict = {}

    policy_type_map = {
        1: 'Custom',
        2: 'BuiltIn',
        3: 'Static'
    }

    bicep_dict['Name'] = translate_to_bicep(az_dump_dict['Name'])
    bicep_dict['PolicyType'] = translate_to_bicep(policy_type_map[az_dump_dict['Properties']['PolicyType']])
    for key in bicep_keys:
        bicep_dict[key] = translate_to_bicep(az_dump_dict['Properties'][key])

    return bicep_dict

def _azpolicy_type_to_bicep(az_type: str) -> str:
    type_map = {
        'String': 'string',
        'DateTime': 'string',
        'Float': 'string',
        'Integer': 'int',
        'Boolean': 'bool',
        'Array': 'array',
        'Object': 'object'
    }
    return type_map[az_type]

def generate_parameter_section(definition_dict: dict) -> dict:
    if definition_dict['Properties']['Parameters'] is None:
        return {'policy_parameters': '', 'bicep_params': ''}

    policy_parameters = ''
    parameter_template = """
    {name}: {{
        type: {type}{allowed_values_string}{default_value_string}
    }}"""

    bicep_params = ''
    # splitting these up because allowed values and default value are optional
    bicep_param_allowed_tmeplate = """\n@allowed({allowedValuesBicepArray})"""
    bicep_param_tmeplate = """\nparam {parameter_name} {type_bicep} = {defaultValueBicep}\n"""

    for name, parameter in definition_dict['Properties']['Parameters'].items():
        default_value_string = indentString(f"\ndefaultValue: {name}DefaultValue", indent_level=2, indent_first_line=False) if parameter.get('defaultValue') is not None else ''
        allowed_values_string = indentString(f"\nallowedValues: {translate_to_bicep(parameter['allowedValues'])}", indent_level=2, indent_first_line=False) if parameter.get('allowedValues') is not None else ''
        policy_parameters += parameter_template.format(name=name,type=translate_to_bicep(parameter['type']), default_value_string=default_value_string, allowed_values_string=allowed_values_string)

        bicep_params += bicep_param_allowed_tmeplate.format(allowedValuesBicepArray=translate_to_bicep(parameter['allowedValues'])) if parameter.get('allowedValues') is not None and parameter.get('defaultValue') is not None else ''
        bicep_params += bicep_param_tmeplate.format(parameter_name=f"{name}DefaultValue", type_bicep=_azpolicy_type_to_bicep(parameter['type']), defaultValueBicep=translate_to_bicep(parameter['defaultValue'])) if parameter.get('defaultValue') is not None else ''
    
    if policy_parameters:
        policy_parameters += '\n'   # so the overall policy object closing bracket is on a new line

    return {'policy_parameters': policy_parameters, 'bicep_params': bicep_params}

def generate_bicep_definition(definition_dict: dict) -> str:
    policies = generate_parameter_section(definition_dict)

    bicep_policy_template = """targetScope = 'managementGroup'
{bicep_params}

var parameters = {{{policy_parameters}}}
var policyRule = {PolicyRule}

resource policy_definition 'Microsoft.Authorization/policyDefinitions@2021-06-01' = {{
    name: {Name}
    properties: {{
        description: {Description}
        displayName: {DisplayName}
        mode: {Mode}
        parameters: parameters
        policyRule: policyRule
        policyType: {PolicyType}
    }}
}}


output ID string = policy_definition.id
output displayName string = policy_definition.properties.displayName
"""

    return bicep_policy_template.format( **_translate_definition(definition_dict), **policies )

def process_policy_definitions(definitions_file: dict, output_dir: str = "./policies/definitions") -> None:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    for definition in definitions_file:
        definition_bicep = generate_bicep_definition(definition)
        file_path = f"{output_dir}/{definition['Name']}.bicep"
        _write_bicep_file(file_path, definition_bicep)

    return


def main():
    definitions_file = argv[1]
    root_output_directory = argv[-1]

    definitions_directory = f"{root_output_directory}/definitions"
    process_policy_definitions(_load_json_dump(definitions_file), definitions_directory)

    return

if __name__ == "__main__": 
    main()
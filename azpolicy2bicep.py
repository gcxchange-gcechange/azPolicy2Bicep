import json
from sys import argv
from pathlib import Path

from helpers import indent, translate_to_bicep, indentString

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

def _translate_set(az_dump_dict: dict) -> dict:
    bicep_keys = ['Description', 'DisplayName', 'PolicyDefinitions', 'PolicyDefinitionGroups']
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

def _python_type_to_bicep(value: type) -> str:
    type_map = {
        "<class 'str'>": 'string',
        "<class 'float'>": 'string',
        "<class 'int'>": 'int',
        "<class 'bool'>": 'bool',
        "<class 'list'>": 'array',
        "<class 'dict'>": 'object'
    }
    return type_map[str(value)]

def generate_definition_parameter_section(definition_dict: dict) -> dict:
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
    policies = generate_definition_parameter_section(definition_dict)

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


def generate_set_parameter_section(definition_dict: dict) -> str:
    bicep_params = ''
    # splitting these up because allowed values and default value are optional
    bicep_param_allowed_tmeplate = """\n@allowed({allowedValuesBicepArray})"""
    bicep_param_tmeplate = """\nparam {parameter_name} {type_bicep} = {valueBicep}\n"""

    for policy in definition_dict['Properties']['PolicyDefinitions']:
        policyDefinitionId = policy['policyDefinitionId'].split('/')
        if policy['parameters'] is None:
            continue

        for name, parameter in policy['parameters'].items():
            bicep_params += bicep_param_allowed_tmeplate.format(allowedValuesBicepArray=translate_to_bicep(parameter['allowedValues'])) if parameter.get('allowedValues') is not None and parameter.get('defaultValue') is not None else ''
            bicep_params += bicep_param_tmeplate.format(parameter_name=f"{policyDefinitionId[-1].replace('-', '')}_{name}", type_bicep=_python_type_to_bicep(type(parameter['value'])), valueBicep=translate_to_bicep(parameter['value']))
    
    return bicep_params

def generate_set_policy_def_section(set_dict: dict) -> str:
    policy_set_definitions = []
    
    for policy in set_dict['Properties']['PolicyDefinitions']:
        policy_set_definition = policy.copy()
        template_strings = []
        format_strings = {}

        policyDefinitionId = policy_set_definition['policyDefinitionId'].split('/')
        if policyDefinitionId[1] == 'subscriptions':    # custom definition
            policy_set_definition['policyDefinitionId'] = "{policyDefinitionId}"
            format_strings['policyDefinitionId'] = f"{policyDefinitionId[-1].replace('-', '_')}.outputs.ID"
            template_strings.append(policy_set_definition['policyDefinitionId'])

            policy_set_definition['policyDefinitionReferenceId'] = "{policyDefinitionReferenceId}"
            format_strings['policyDefinitionReferenceId'] = f"toLower(replace({policyDefinitionId[-1].replace('-', '_')}.outputs.displayName, ' ', '-'))"
            template_strings.append(policy_set_definition['policyDefinitionReferenceId'])

        if policy['parameters'] is not None:
            for name in policy['parameters'].keys():
                policy_set_definition['parameters'][name]['value'] = f"{{{policyDefinitionId[-1].replace('-', '')}_{name}}}"
                format_strings[f"{policyDefinitionId[-1].replace('-', '')}_{name}"] = f"{policyDefinitionId[-1].replace('-', '')}_{name}"
                template_strings.append(policy_set_definition['parameters'][name]['value'])
        policy_set_definitions.append( indent() + translate_to_bicep(policy_set_definition, nested=True, template=template_strings).format_map(format_strings))

    return '[\n' + '\n'.join(policy_set_definitions) + '\n]'

def generate_set_modules_section(set_dict: dict) -> str:
    bicep_modules_string = ''
    bicep_module_template = """module {name_underscores} '../definitions/{name}.bicep' = {{
    name: '{name}'
}}"""

    for policy in set_dict['Properties']['PolicyDefinitions']:
        policyDefinitionId = policy['policyDefinitionId'].split('/')
        if policyDefinitionId[1] == 'providers':    # built-in definition
            continue

        bicep_modules_string += bicep_module_template.format(name=policyDefinitionId[-1], name_underscores=policyDefinitionId[-1].replace('-', '_'))

    return bicep_modules_string

def generate_bicep_policy_set(set_dict: dict) -> str:
    set_parameters = generate_set_parameter_section(set_dict)

    bicep_policy_template = """targetScope = 'managementGroup'
{bicep_params}

var policyDefinitionGroups = {PolicyDefinitionGroups}
var policyDefinitions = {policyDefinitions}


resource policySet 'Microsoft.Authorization/policySetDefinitions@2020-03-01' = {{
    name: {Name}
    properties: {{
        displayName: {DisplayName}
        policyDefinitionGroups: policyDefinitionGroups
        policyDefinitions: policyDefinitions
    }}
}}


// definitions from modules
{definition_modules}


output ID string = policySet.id
"""

    return bicep_policy_template.format( **_translate_set(set_dict), bicep_params=set_parameters, policyDefinitions=generate_set_policy_def_section(set_dict), definition_modules=generate_set_modules_section(set_dict) )

def process_policy_sets(initiatives_file: dict, output_dir: str = "./policies/initiatives") -> None:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    for set in initiatives_file:
        set_bicep = generate_bicep_policy_set(set)
        file_path = f"{output_dir}/{set['Name']}.bicep"
        _write_bicep_file(file_path, set_bicep)

    return

def main():
    definitions_file = argv[1]
    root_output_directory = argv[-1]

    definitions_directory = f"{root_output_directory}/definitions"
    process_policy_definitions(_load_json_dump(definitions_file), definitions_directory)

    return

if __name__ == "__main__": 
    main()
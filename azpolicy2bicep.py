from helpers import translate_to_bicep

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

def generate_parameter_section(definition_dict: dict) -> dict:
    if definition_dict['Properties']['Parameters'] is None:
        return {'policy_parameters': '', 'bicep_params': ''}

    policy_parameters = ''

    parameter_template = """
    {name}: {{
        type: {type}{default_value_string}{allowed_values_string}
    }}
"""

    bicep_params = ""
    # splitting these up because allowed values and default value are optional
    bicep_param_allowed_tmeplate = """@allowed({allowedValuesBicepArray})"""
    bicep_param_tmeplate = """param {parameter_name} {type_bicep} = {defaultValueBicep}"""

    for name, parameter in definition_dict['Properties']['Parameters'].items():
        default_value_string = f"\ndefaultValue: {translate_to_bicep(parameter['defaultValue'])}" if parameter.get('defaultValue') is not None else ''
        allowed_values_string = f"\nallowedValues: {translate_to_bicep(parameter['allowedValues'])}" if parameter.get('allowedValues') is not None else ''
        policy_parameters += parameter_template.format(name=name,type=translate_to_bicep(parameter['type']), default_value_string=default_value_string, allowed_values_string=allowed_values_string)

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
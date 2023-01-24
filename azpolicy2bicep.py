import json
from sys import argv
from pathlib import Path

from helpers import indent, translate_to_bicep, indentString, quote_special, enumerate_duplicate_display_names, generate_reference_dict, specials_to_underscore

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
    bicep_dict['DeploymentName'] = translate_to_bicep(f"Definition-{specials_to_underscore(az_dump_dict['Properties']['DisplayName'])}")
    if len(bicep_dict['DeploymentName']) > 64:
        bicep_dict['DeploymentName'] = f"substring({bicep_dict['DeploymentName']}, 0, 64)"
        
    for key in bicep_keys:
        bicep_dict[key] = translate_to_bicep(az_dump_dict['Properties'][key])

    return bicep_dict

def _translate_set(az_dump_dict: dict) -> dict:
    bicep_keys = ['Description', 'DisplayName', 'PolicyDefinitions', 'PolicyDefinitionGroups']
    default_empty = {
        'Description': '',
        'DisplayName': '',
        'PolicyDefinitions': [],
        'PolicyDefinitionGroups': []
    }
    bicep_dict = {}

    policy_type_map = {
        1: 'Custom',
        2: 'BuiltIn',
        3: 'Static'
    }

    bicep_dict['Name'] = translate_to_bicep(az_dump_dict['Name'])
    bicep_dict['PolicyType'] = translate_to_bicep(policy_type_map[az_dump_dict['Properties']['PolicyType']])
    bicep_dict['DeploymentName'] = translate_to_bicep(f"Initiative-{specials_to_underscore(az_dump_dict['Properties']['DisplayName'])}")
    for key in bicep_keys:
        bicep_dict[key] = translate_to_bicep(az_dump_dict['Properties'][key]) if az_dump_dict['Properties'].get(key) is not None else translate_to_bicep(default_empty[key])

    return bicep_dict

def _translate_assignment(az_dump_dict: dict, defset_reference: dict) -> dict:
    bicep_keys = ['Description', 'DisplayName', 'PolicyDefinitionId', 'NonComplianceMessages']
    default_empty = {
        'Description': '',
        'DisplayName': '',
        'NonComplianceMessages': []
    }
    bicep_dict = {}

    enforcement_mode_map = {
        0: 'Default',
        1: 'DoNotEnforce'
    }

    bicep_dict['Name'] = translate_to_bicep(az_dump_dict['Name'])
    bicep_dict['EnforcementMode'] = translate_to_bicep(enforcement_mode_map[az_dump_dict['Properties']['EnforcementMode']])
    bicep_dict['DeploymentName'] = translate_to_bicep(f"Assignment-{specials_to_underscore(az_dump_dict['Properties']['DisplayName'])}")
    for key in bicep_keys:
        bicep_dict[key] = translate_to_bicep(az_dump_dict['Properties'][key]) if az_dump_dict['Properties'].get(key) is not None else translate_to_bicep(default_empty[key])

    definition_id_parts = az_dump_dict['Properties']['PolicyDefinitionId'].split('/')
    if definition_id_parts[1] == 'subscriptions' or definition_id_parts[3] == 'managementGroups':
        bicep_dict['PolicyDefinitionId'] = "policy.outputs.ID"

    return bicep_dict

def _translate_exemption(az_dump_dict: dict) -> dict:
    bicep_keys = ['Description', 'DisplayName', 'PolicyAssignmentId', 'ExemptionCategory']
    default_empty = {
        'Description': '',
        'DisplayName': '',
        'ExemptionCategory': ''
    }
    bicep_dict = {}

    bicep_dict['Name'] = translate_to_bicep(az_dump_dict['Name'])
    bicep_dict['DeploymentName'] = translate_to_bicep(f"Exemption-{specials_to_underscore(az_dump_dict['Properties']['DisplayName'])}")
    for key in bicep_keys:
        bicep_dict[key] = translate_to_bicep(az_dump_dict['Properties'][key]) if az_dump_dict['Properties'].get(key) is not None else translate_to_bicep(default_empty[key])

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

### definitions
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

module policy_definition '../../example_modules/policy_definition.bicep' = {{
    name: {DeploymentName}
    params: {{
        name: {Name}
        description: {Description}
        displayName: {DisplayName}
        mode: {Mode}
        parameters: parameters
        policyRule: policyRule
        policyType: {PolicyType}
    }}
}}


output ID string = policy_definition.outputs.ID
output displayName string = policy_definition.outputs.displayName
"""

    return bicep_policy_template.format( **_translate_definition(definition_dict), **policies )

def process_policy_definitions(definitions_file: dict, output_dir: str = "./policies/definitions") -> None:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    
    for definition in enumerate_duplicate_display_names(definitions_file):
        definition_bicep = generate_bicep_definition(definition)
        file_path = f"{output_dir}/{definition['Properties']['DisplayName']}.bicep"
        _write_bicep_file(file_path, definition_bicep)

    return

### initiatives / policy sets
def generate_set_parameter_section(definition_dict: dict) -> dict:
    if definition_dict['Properties']['Parameters'] is None:
        return {'set_parameters': '', 'bicep_params': ''}

    set_parameters = ''
    parameter_template = """
    {name}: {{
        type: {type}{allowed_values_string}{default_value_string}
    }}"""

    bicep_params = ''
    # splitting these up because allowed values and default value are optional
    bicep_param_allowed_tmeplate = """\n@allowed({allowedValuesBicepArray})"""
    bicep_param_tmeplate = """\nparam {parameter_name} {type_bicep} = {valueBicep}\n"""

    for name, parameter in definition_dict['Properties']['Parameters'].items():
        default_value_string = indentString(f"\ndefaultValue: {specials_to_underscore(name)}DefaultValue", indent_level=2, indent_first_line=False) if parameter.get('defaultValue') is not None else ''
        allowed_values_string = indentString(f"\nallowedValues: {translate_to_bicep(parameter['allowedValues'])}", indent_level=2, indent_first_line=False) if parameter.get('allowedValues') is not None else ''
        set_parameters += parameter_template.format(name=quote_special(name),type=translate_to_bicep(parameter['type']), default_value_string=default_value_string, allowed_values_string=allowed_values_string)

        bicep_params += bicep_param_allowed_tmeplate.format(allowedValuesBicepArray=translate_to_bicep(parameter['allowedValues'])) if parameter.get('allowedValues') is not None and parameter.get('defaultValue') is not None else ''
        bicep_params += bicep_param_tmeplate.format(parameter_name=specials_to_underscore(f"{name}DefaultValue"), type_bicep=_azpolicy_type_to_bicep(parameter['type']), valueBicep=translate_to_bicep(parameter['defaultValue'])) if parameter.get('defaultValue') is not None else ''
    
    if set_parameters:
        set_parameters += '\n'   # so the overall set parameter object closing bracket is on a new line

    return  {'set_parameters': set_parameters, 'bicep_params': bicep_params}

def generate_set_policy_def_section(set_dict: dict, definitions_reference: dict) -> str:
    policy_set_definitions = []
    
    for policy in set_dict['Properties']['PolicyDefinitions']:
        policy_set_definition = policy.copy()
        template_strings = []
        format_strings = {}

        policyDefinitionId = policy_set_definition['policyDefinitionId'].split('/')
        if policyDefinitionId[1] == 'subscriptions' or policyDefinitionId[3] == 'managementGroups':    # custom definition
            definition_reference_name = "module_" + specials_to_underscore(definitions_reference[policyDefinitionId[-1]]['DisplayName'])
            policy_set_definition['policyDefinitionId'] = "{policyDefinitionId}"
            format_strings['policyDefinitionId'] = f"{definition_reference_name}.outputs.ID"
            template_strings.append(policy_set_definition['policyDefinitionId'])

            policy_set_definition['policyDefinitionReferenceId'] = "{policyDefinitionReferenceId}"
            format_strings['policyDefinitionReferenceId'] = f"toLower(replace({definition_reference_name}.outputs.displayName, ' ', '-'))"
            template_strings.append(policy_set_definition['policyDefinitionReferenceId'])
        
            policy_set_definitions.append( indent() + translate_to_bicep(policy_set_definition, nested=True, template=template_strings).format_map(format_strings) )
            continue

        policy_set_definitions.append( indent() + translate_to_bicep(policy_set_definition, nested=True) )

    return '[\n' + '\n'.join(policy_set_definitions) + '\n]'

def generate_set_modules_section(set_dict: dict, definitions_reference: dict) -> str:
    bicep_modules = []
    bicep_module_template = """module module_{name_underscores} '../definitions/{name}.bicep' = {{
    name: substring('Submodule-{name_underscores}', 0, 64)
}}"""

    for policy in set_dict['Properties']['PolicyDefinitions']:
        policyDefinitionId = policy['policyDefinitionId'].split('/')
        if policyDefinitionId[1] == 'providers' and policyDefinitionId[2] == 'Microsoft.Authorization':    # built-in definition
            continue

        definition_display_name = definitions_reference[policyDefinitionId[-1]]['DisplayName']
        bicep_modules.append( bicep_module_template.format(name=definition_display_name, name_underscores=specials_to_underscore(definition_display_name)) )

    return '\n'.join(bicep_modules)

def generate_bicep_policy_set(set_dict: dict, definitions_reference: dict) -> str:
    parameters_dict = generate_set_parameter_section(set_dict)

    bicep_policy_template = """targetScope = 'managementGroup'
{bicep_params}

var policyDefinitionGroups = {PolicyDefinitionGroups}
var parameters = {{{setParameters}}}
var policyDefinitions = {policyDefinitions}


module policySet '../../example_modules/initiative.bicep' = {{
    name: substring({DeploymentName}, 0, 64)
    params: {{
        name: {Name}
        displayName: {DisplayName}
        parameters: parameters
        policyDefinitionGroups: policyDefinitionGroups
        policyDefinitions: policyDefinitions
    }}
}}


// definitions from modules
{definition_modules}


output ID string = policySet.outputs.ID
"""

    return bicep_policy_template.format( **_translate_set(set_dict), bicep_params=parameters_dict['bicep_params'], setParameters=parameters_dict['set_parameters'], 
        policyDefinitions=generate_set_policy_def_section(set_dict, definitions_reference), definition_modules=generate_set_modules_section(set_dict, definitions_reference) )

def process_policy_sets(initiatives_file: dict, definitions_file: list, output_dir: str = "./policies/initiatives") -> None:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    definitions_reference = generate_reference_dict(definitions_file)
    for set in enumerate_duplicate_display_names(initiatives_file):
        set_bicep = generate_bicep_policy_set(set, definitions_reference)
        file_path = f"{output_dir}/{set['Properties']['DisplayName']}.bicep"
        _write_bicep_file(file_path, set_bicep)

    return

### assignments
def generate_assignment_parameter_section(assignment_dict: dict) -> dict:
    if assignment_dict['Properties']['Parameters'] is None:
        return {'assignment_parameters': '', 'bicep_params': ''}

    assignment_parameters = ''
    parameter_template = """
    {name}: {{
        value: {value}
    }}"""

    bicep_params = ''
    # splitting these up because allowed values and default value are optional
    bicep_param_allowed_tmeplate = """\n@allowed({allowedValuesBicepArray})"""
    bicep_param_tmeplate = """\nparam {parameter_name} {type_bicep} = {valueBicep}\n"""

    for name, parameter in assignment_dict['Properties']['Parameters'].items():
        name_dashless =  specials_to_underscore(name)
        assignment_parameters += parameter_template.format(name=quote_special(name), value=name_dashless)   # the value comes from the bicep parameter that shares the name of the policy parameter

        bicep_params += bicep_param_allowed_tmeplate.format(allowedValuesBicepArray=translate_to_bicep(parameter['allowedValues'])) if parameter.get('allowedValues') is not None and parameter.get('defaultValue') is not None else ''
        bicep_params += bicep_param_tmeplate.format(parameter_name=name_dashless, type_bicep=_python_type_to_bicep(type(parameter['value'])), valueBicep=translate_to_bicep(parameter['value']))
    
    if assignment_parameters:
        assignment_parameters += '\n'   # so the overall set parameter object closing bracket is on a new line

    return  {'assignment_parameters': assignment_parameters, 'bicep_params': bicep_params}

def generate_assignment_modules_section(assignment_dict: dict, initiatives_definitions_reference: dict) -> str:
    bicep_modules_string = ''
    bicep_module_template = """
module policy '../{def_type}/{name}.bicep' = {{
    name: substring('Submodule-{deployment_name}', 0, 64)
}}
"""

    defset_type_map = {
        'policyDefinitions': 'definitions',
        'policySetDefinitions': 'initiatives'
    }

    policyDefinitionId = assignment_dict['Properties']['PolicyDefinitionId'].split('/')
    if policyDefinitionId[1] == 'providers' and policyDefinitionId[2] == 'Microsoft.Authorization':    # built-in definition
        return ''

    def_type = defset_type_map[policyDefinitionId[-2]]
    display_name = initiatives_definitions_reference[def_type][policyDefinitionId[-1]]['DisplayName']
    bicep_modules_string += bicep_module_template.format(name=display_name, def_type=def_type, deployment_name=specials_to_underscore(display_name))

    return bicep_modules_string

def generate_bicep_policy_assignment(assignment_dict: dict, initiatives_definitions_reference: dict) -> str:
    parameters_dict = generate_assignment_parameter_section(assignment_dict)

    bicep_policy_template = """targetScope = 'managementGroup'


@allowed([
  'Default'
  'DoNotEnforce'
])
@description('Policy assignment enforcement mode.')
param enforcementMode string = {EnforcementMode}
{bicep_params}

var parameters = {{{assignmentParameters}}}

module assignment '../../example_modules/policy_assignment.bicep' = {{
  name: substring({DeploymentName}, 0, 64)
  params: {{
    name: {Name}
    displayName: {DisplayName}
    policyDefinitionId: {PolicyDefinitionId}
    parameters: parameters
    enforcementMode: enforcementMode
  }}
}}
{definition_modules}"""

    return bicep_policy_template.format( **_translate_assignment(assignment_dict, initiatives_definitions_reference), bicep_params=parameters_dict['bicep_params'], 
        assignmentParameters=parameters_dict['assignment_parameters'], definition_modules=generate_assignment_modules_section(assignment_dict, initiatives_definitions_reference))

def process_policy_assignments(assignments_file: dict, definitions_file: list, initiatives_file: list, output_dir: str = "./policies/assignments") -> None:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    initiatives_definitions_reference = { 'definitions': generate_reference_dict(definitions_file), 'initiatives': generate_reference_dict(initiatives_file)} 
    for assignment in enumerate_duplicate_display_names(assignments_file):
        assignment_bicep = generate_bicep_policy_assignment(assignment, initiatives_definitions_reference)
        file_path = f"{output_dir}/{assignment['Properties']['DisplayName']}.bicep"
        _write_bicep_file(file_path, assignment_bicep)

    return

## exemptions
def generate_bicep_policy_exemption(exemption_dict: dict) -> str:
    bicep_policy_template = """


module exemption '../../example_modules/policy_exemption.bicep' = {{
    name: substring({DeploymentName}, 0, 64)
    params: {{
        name: {Name}
        displayName: {DisplayName}
        description: {Description}
        policyAssignmentId: {PolicyAssignmentId}
        exemptionCategory: {ExemptionCategory}
    }}
}}
"""

    return bicep_policy_template.format( **_translate_exemption(exemption_dict) )

def process_policy_exemptions(exemptions_file: dict, output_dir: str = "./policies/exemptions") -> None:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    for exemption in enumerate_duplicate_display_names(exemptions_file):
        exemption_bicep = generate_bicep_policy_exemption(exemption)
        file_path = f"{output_dir}/{exemption['Properties']['DisplayName']}.bicep"
        _write_bicep_file(file_path, exemption_bicep)

    return

def main():
    definitions_file = argv[1]
    initiatives_file = argv[2]
    assignments_file = argv[3]
    exemptions_file = argv[4]
    root_output_directory = argv[-1]

    definitions_list = enumerate_duplicate_display_names(_load_json_dump(definitions_file))
    initiatives_list = enumerate_duplicate_display_names(_load_json_dump(initiatives_file))
    definitions_directory = f"{root_output_directory}/definitions"
    initiatives_directory = f"{root_output_directory}/initiatives"
    assignments_directory = f"{root_output_directory}/assignments"
    exemptions_directory = f"{root_output_directory}/exemptions"
    process_policy_definitions(definitions_list, definitions_directory)
    process_policy_sets(initiatives_list, definitions_list, initiatives_directory)
    process_policy_assignments(_load_json_dump(assignments_file), definitions_list, initiatives_list, assignments_directory)
    process_policy_exemptions(_load_json_dump(exemptions_file), exemptions_directory)

    return

if __name__ == "__main__": 
    main()
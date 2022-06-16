

def translate_to_bicep(not_bicep: str, type_given: str = '', nested: bool = False, template: bool = False) -> str:
    if type(not_bicep) in [int, bool] \
            or type_given.lower() in ['int', 'boolean']:
        return f"{not_bicep}"

    if isinstance(not_bicep, str) \
            or type_given.lower() in ['string', 'datetime']:
        if template and not_bicep in template:
            return not_bicep
        bicepString = not_bicep.replace("'", "\\'")
        return f"'{bicepString}'"

    if type_given.lower() == 'array' or type(not_bicep) is list:
        if len(not_bicep) < 1:
            return '[]'

        bicep_array = '[\n'
        for item in not_bicep:
            bicep_array += f"{indent()}{translate_to_bicep(item, nested=True, template=[])}\n"
        bicep_array += ']'
        return indentString(bicep_array, nested, indent_first_line=False)

    if type_given.lower() == 'object' or type(not_bicep) is dict:
        if len(not_bicep) < 1:
            if template:
                return '{{}}'
            return '{}'

        bicep_object = '{\n'
        if template:
            bicep_object = '{{\n'
        for key, value in not_bicep.items():
            bicep_object += f"{indent()}{key}: {translate_to_bicep(value, nested=True, template=template)}\n"
        bicep_object += "}"
        if template:
            bicep_object += "}"
        return indentString(bicep_object, nested, indent_first_line=False)

    return f"'{not_bicep}'" # mostly for floats, bicep doesn't have non-int number types


def indent(indent_level: int = 1) -> str:
    return " " * 4 * indent_level

def indentString(input_string: str, indent_level: int = 1, indent_first_line: bool = True) -> str:
    lines = input_string.splitlines()

    indented_string = ''.join([indent(indent_level * indent_first_line), lines.pop(0)])
    for line in lines:
        indented_string = ''.join([indented_string, '\n', indent(indent_level), line])

    return indented_string

def detect_pwsh_dump(policy_dump) -> bool:
    # will use the fact that the name field is present in all dumps 
    # and is capitalize in powershell dumps as most keys are
    
    if isinstance(policy_dump, list) and 'Name' in policy_dump[0].keys():
        return True
    
    if isinstance(policy_dump, dict) and 'Name' in policy_dump.keys():
        return True

    return False
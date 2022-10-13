from re import search, sub

def quote_special(string: str) -> str:
    specials_regex = '[-!@#$%^&*;:"\'~`><.,?+=/\\\[\]\{\}\(\)\s]'
    return f"'{string}'" if search( specials_regex, string ) is not None else string

def specials_to_underscore(string: str) -> str:
    specials_regex = '[-!@#$%^&*;:"\'~`><.,?+=/\\\[\]\{\}\(\)\s]'
    return sub(specials_regex, '_', string)

def translate_to_bicep(not_bicep: str, type_given: str = '', nested: bool = False, template: bool = False) -> str:
    if type(not_bicep) in [int, bool] \
            or type_given.lower() in ['int', 'boolean']:
        return f"{not_bicep}".lower()   # bicep only accepts all-lower-case booleans

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
            bicep_object += f"{indent()}{quote_special(key)}: {translate_to_bicep(value, nested=True, template=template)}\n"
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

def enumerate_duplicate_display_names(policy_dump: list) -> list:
    policy_dump_no_dupes = []
    display_names_map = {}
    for policy in policy_dump:
        no_dupes_policy = policy

        display_name = policy["Properties"].get("DisplayName")
        name_count = display_names_map.get(display_name) + 1 if display_names_map.get(display_name) is not None else 1
        if name_count > 1: ## seen this one before
            display_name = f"{display_name}_{name_count}"
            no_dupes_policy["Properties"]["DisplayName"] = display_name
        
        display_names_map[display_name] = name_count
        policy_dump_no_dupes.append(no_dupes_policy)

    return policy_dump_no_dupes

def generate_reference_dict( policy_dump: list ) -> dict:
    reference_dict = {}

    for policy in policy_dump:
        reference_dict[policy['Name']] = {}
        reference_dict[policy['Name']]['DisplayName'] = policy["Properties"]["DisplayName"]

    return reference_dict


def translate_to_bicep(not_bicep: str, type_given: str = '', nested: bool = False) -> str:
    if type(not_bicep) in [int, bool] \
            or type_given.lower() in ['int', 'boolean']:
        return f"{not_bicep}"

    if isinstance(not_bicep, str) \
            or type_given.lower() in ['string', 'datetime']:
        bicepString = not_bicep.replace("'", "\\'")
        return f"'{bicepString}'"

    if type_given.lower() == 'array' or type(not_bicep) is list:
        bicep_array = "[\n"
        for item in not_bicep:
            bicep_array += f"{indent()}{translate_to_bicep(item, nested=True)}\n"
        bicep_array += "]"
        return indentString(bicep_array, nested, indent_first_line=False)

    if type_given.lower() == 'object' or type(not_bicep) is dict:
        bicep_object = "{\n"
        for key, value in not_bicep.items():
            bicep_object += f"{indent()}{key}: {translate_to_bicep(value, nested=True)}\n"
        bicep_object += "}"
        return indentString(bicep_object, nested, indent_first_line=False)

    return f"'{not_bicep}'" # mostly for floats, bicep doesn't have non-int number types


def indent(indent_level: int = 1) -> str:
    return "    " * indent_level

def indentString(input_string: str, indent_level: int = 1, indent_first_line: bool = True) -> str:
    lines = input_string.splitlines()

    indented_string = ''.join([indent(indent_level * indent_first_line), lines.pop(0)])
    for line in lines:
        indented_string = ''.join([indented_string, '\n', indent(indent_level), line])

    return indented_string


def translate_to_bicep(not_bicep: str, type_given: str = '') -> str:
    if type(not_bicep) in [int, bool, float] \
            or type_given.lower() in ['int', 'boolean', 'float']:
        return f"{not_bicep}"

    if isinstance(not_bicep, str) \
            or type_given.lower() in ['string', 'datetime']:
        bicepString = not_bicep.replace("'", "\\'")
        return f"'{bicepString}'"

    if type_given.lower() == 'array' or type(not_bicep) is list:
        bicep_array = "[\n"
        for item in not_bicep:
            bicep_array += f"    {translate_to_bicep(item)}\n"
        bicep_array += "]\n"
        return bicep_array

    if type_given.lower() == 'object' or type(not_bicep) is dict:
        bicep_object = "{\n"
        for key, value in not_bicep.items():
            bicep_object += f"    {key}: {translate_to_bicep(value)}\n"
        bicep_object += "}\n"
        return bicep_object

    return f"'{not_bicep}'"
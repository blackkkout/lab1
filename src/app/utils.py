def validate_password(password: str):
    has_lowercase = any(char.islower() for char in password)
    has_uppercase = any(char.isupper() for char in password)
    has_numbers = any(char.isnumeric() for char in password)
    if has_lowercase and has_uppercase and has_numbers and len(password) >= 8:
        return "strong"
    else:
        return "weak"

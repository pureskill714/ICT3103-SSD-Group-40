import re

from wtforms import ValidationError

CLEANR = re.compile('<.*?>|&([a-z0-9]+|#[0-9]{1,6}|#x[0-9a-f]{1,6});')


def cleanhtml(raw_html):
    cleantext = re.sub(CLEANR, '', raw_html)
    return cleantext


def password_policy_check(form, field):
    # Convert string to list of characters
    password = list(field.data)

    # Count lowercase, uppercase and numbers
    lowers = uppers = digits = 0
    for ch in password:
        if ch.islower():
            lowers += 1
        if ch.isupper():
            uppers += 1
        if ch.isdigit():
            digits += 1

    # Password must have one lowercase letter, one uppercase letter and one digit
    is_valid = lowers and uppers and digits
    if not is_valid:
        raise ValidationError(
            'Password must have at least one lowercase letter, one uppercase letter and one number')

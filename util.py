import re
from urllib.parse import urlunsplit, urlsplit

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

def make_safe_url(url):
    """Makes a URL safe by removing optional hostname and port.
    Example:
        | ``make_safe_url('https://hostname:80/path1/path2?q1=v1&q2=v2#fragment')``
        | returns ``'/path1/path2?q1=v1&q2=v2#fragment'``
    Override this method if you need to allow a list of safe hostnames.
    """

    # Split the URL into scheme, netloc, path, query and fragment
    parts = list(urlsplit(url))

    # Clear scheme and netloc and rebuild URL
    parts[0] = ''   # Empty scheme
    parts[1] = ''   # Empty netloc (hostname:port)
    safe_url = urlunsplit(parts)
    return safe_url



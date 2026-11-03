"""Pure diagnostic sanitization; never include session headers or fixture passwords."""
import re


def redact_diagnostics(data, secrets=()):
    text = data.decode(errors='replace')
    text = re.sub(r'''(?im)^.*(?:cookie|authorization)["']?\s*[:=].*$''', '[redacted credential header]', text)
    for value in secrets:
        if value:
            text = text.replace(value, '[redacted fixture credential]')
    return text

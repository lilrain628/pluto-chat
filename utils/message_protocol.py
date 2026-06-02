MESSAGE_PREFIX = "PLUTOCHAT:"


def add_message_prefix(message):
    return f"{MESSAGE_PREFIX}{message}"


def remove_message_prefix(message):
    if not message.startswith(MESSAGE_PREFIX):
        return None
    return message[len(MESSAGE_PREFIX):]

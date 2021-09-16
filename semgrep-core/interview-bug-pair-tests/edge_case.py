def contrived_ok(user_input):
    use_value("DEFAULT_VALUE")
    # ok: resetting-value
    use_value(user_input)


def contrived_example(user_input):
    use_value(user_input)
    # rule_id: resetting-value
    use_value("DEFAULT_VALUE")

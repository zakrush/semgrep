def contrived_ok(user_input):
    set(user_input)
    # ok: resetting-value
    lock(user_input)


def contrived_example(user_input):
    lock(user_input)
    # rule_id: resetting-value
    set(user_input)

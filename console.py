from cipher import validate_key


def show(title, fields):
    print(f"\n[{title}]")
    width = max(len(label) for label in fields)
    for label, value in fields.items():
        print(f"  {label:<{width}} : {value}")


def read_key(prompt):
    while True:
        try:
            return validate_key(input(prompt))
        except ValueError as error:
            print(f"  {error}")


def show_commands(commands):
    print("\nPerintah:")
    width = max(len(name) for name in commands)
    for name, (_, description) in commands.items():
        print(f"  {name:<{width}}  {description}")

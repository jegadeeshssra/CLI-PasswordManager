import typer

app = typer.Typer()

@app.command()
def hello(name: str):
    print(f"Hello {name}")

if __name__ == "__main__":
    app()

# When you write app = typer.Typer(), you create an instance of a Typer application. 
# This is like creating an object that will hold all your application logic and commands. 
# The Typer object contains the framework for your CLI, but it's not yet "doing" anything until you tell it to run.

# if __name__ == "__main__":: This checks if the script is being run directly (not imported as a module).
#   - When Python executes a script, it sets a special variable __name__. If the script is run directly, __name__ is 
#   set to "__main__". If the script is imported as a module in another script, __name__ will be set to the module 
#   name.
#   - This block ensures that the code inside it runs only when the script is executed directly, not when imported.

# - app() actually calls the __call__ method of the app object, which is an instance of the Typer class. This method 
#   is defined in the Typer class (which comes from the typer library). The __call__ method allows an object to behave 
#   like a function, meaning you can "call" the object itself just like a regular function.

# - The @app.command() decorator is used to mark a function as a CLI command within the Typer application. When you 
#   define a function using this decorator, Typer knows that this function should be associated with a specific 
#   command in the CLI.
# - It tells Typer that a function should be treated as a command in the command-line interface (CLI).
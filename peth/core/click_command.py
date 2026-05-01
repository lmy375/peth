"""
Click-based command system for peth console.
"""

import shlex
import sys
from functools import wraps
from typing import Callable, Optional

import click

# Make every console Click command accept both -h and --help.
CONSOLE_CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


class ClickCommand:
    """Decorator for creating Click-based commands that work with cmd.Cmd."""

    def __init__(self, name: Optional[str] = None, category: Optional[str] = None):
        self.name = name
        self.category = category
        self.click_command = None

    def __call__(self, func: Callable):
        """Make this decorator work with or without parentheses."""
        # Store the original function name
        self.name = self.name or func.__name__

        # Get the Click command if it's already decorated
        if hasattr(func, "callback"):
            # Function is already a Click command — merge our help-option names
            # into whatever context_settings it already has.
            self.click_command = func
            existing = getattr(func, "context_settings", None) or {}
            merged = {**CONSOLE_CONTEXT_SETTINGS, **existing}
            merged["help_option_names"] = CONSOLE_CONTEXT_SETTINGS["help_option_names"]
            func.context_settings = merged
            original_func = func.callback
        else:
            # Create a Click command from the function
            self.click_command = click.command(
                name=self.name, context_settings=CONSOLE_CONTEXT_SETTINGS
            )(func)
            original_func = func

        @wraps(original_func)
        def wrapper(console_self, arg_line: str):
            """Wrapper that adapts Click commands to cmd.Cmd style."""
            # Parse the argument line
            try:
                args = shlex.split(arg_line) if arg_line else []
            except ValueError as e:
                print(f"Error parsing arguments: {e}")
                return

            # Capture Click's output
            old_stdout = sys.stdout
            old_stderr = sys.stderr

            try:
                # make_context honors the command's context_settings
                # (including our help_option_names). standalone_mode lives
                # on Command.main(), not make_context.
                ctx = self.click_command.make_context(self.name, args, obj=console_self)

                # Execute the Click command
                with ctx:
                    result = ctx.invoke(self.click_command.callback, **ctx.params)
                    # Return the result to support exit command
                    return result

            except click.exceptions.Exit:
                # Raised by --help / -h after printing help text. Swallow it.
                pass
            except click.ClickException as e:
                # Handle Click exceptions (missing arguments, bad options, ...)
                e.show()
            except SystemExit:
                pass
            except Exception as e:
                # Handle other exceptions
                if getattr(console_self, "_debug", False):
                    raise
                print(f"Error: {e}")
            finally:
                # Restore stdout/stderr
                sys.stdout = old_stdout
                sys.stderr = old_stderr

        # Store metadata
        wrapper._command_name = self.name
        wrapper._command_category = self.category
        wrapper._is_click_command = True
        wrapper._click_command = self.click_command

        return wrapper


def pass_console(f):
    """
    Decorator that passes the console instance to the Click command.
    Use with @click.pass_context to access both Click context and console.

    Example:
        @command_click()
        @click.argument('address')
        @click.pass_context
        @pass_console
        def my_command(console, ctx, address):
            # console is the PethConsole instance
            # ctx is the Click context
            balance = console.web3.eth.get_balance(address)
    """

    @wraps(f)
    def wrapper(ctx, *args, **kwargs):
        console = ctx.obj  # Get console from Click context
        return f(console, ctx, *args, **kwargs)

    return wrapper


def console_command(name: Optional[str] = None, category: Optional[str] = None):
    """
    Convenience decorator that combines Click command creation with console registration.

    Example:
        @console_command()
        @click.argument('value', type=int)
        @click.option('--double', is_flag=True, help='Double the value')
        def calc(value, double):
            '''Calculate and display a value.'''
            result = value * 2 if double else value
            click.echo(f"Result: {result}")
    """

    def decorator(f):
        # Apply the ClickCommand decorator
        return ClickCommand(name=name, category=category)(f)

    return decorator


# Convenience decorator
command_click = ClickCommand

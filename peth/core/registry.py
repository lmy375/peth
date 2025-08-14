"""
Command registry system for peth console.
"""

import inspect
import os
from functools import wraps
from typing import Callable, Dict, Optional


class CommandRegistry:
    """Registry for console commands."""

    def __init__(self):
        self._commands: Dict[str, Dict[str, Callable]] = {}

    def register(self, name: Optional[str] = None, category: Optional[str] = None):
        """
        Decorator to register a command method.

        Args:
            name: Command name (defaults to method name)
            category: Category for grouping commands (defaults to module name)
        """

        def decorator(func: Callable):
            cmd_name = name or func.__name__

            # Auto-detect category from module name if not provided
            if category is None:
                module = inspect.getmodule(func)
                if module and hasattr(module, "__file__"):
                    # Extract filename without extension
                    filename = os.path.basename(module.__file__)
                    auto_category = os.path.splitext(filename)[0]
                    # Use the filename as category
                    final_category = auto_category
                else:
                    final_category = "general"
            else:
                final_category = category

            if final_category not in self._commands:
                self._commands[final_category] = {}

            self._commands[final_category][cmd_name] = func

            # Store metadata on the function
            func._command_name = cmd_name
            func._command_category = final_category

            @wraps(func)
            def wrapper(self, *args, **kwargs):
                return func(self, *args, **kwargs)

            return wrapper

        return decorator

    def create_category_decorator(self, category: str):
        """
        Create a decorator with a pre-set category.

        Args:
            category: The category to use for all commands decorated with this decorator

        Returns:
            A decorator function that auto-sets the category
        """

        def category_command(name: Optional[str] = None):
            return self.register(name=name, category=category)

        return category_command

    def get_commands(self, category: Optional[str] = None) -> Dict[str, Callable]:
        """Get all registered commands or commands from a specific category."""
        if category:
            return self._commands.get(category, {})

        # Return all commands flattened
        all_commands = {}
        for cat_commands in self._commands.values():
            all_commands.update(cat_commands)
        return all_commands

    def get_categories(self) -> list:
        """Get all command categories."""
        return list(self._commands.keys())

    def bind_to_console(self, console_instance):
        """Bind all registered commands to a console instance."""
        for category, commands in self._commands.items():
            for cmd_name, cmd_func in commands.items():
                # Create the method name with 'do_' prefix
                method_name = f"do_{cmd_name}"

                # Create a wrapper that preserves the docstring
                def make_bound_method(func):
                    def bound_method(arg):
                        return func(console_instance, arg)

                    # Preserve the original docstring
                    bound_method.__doc__ = func.__doc__
                    bound_method.__name__ = method_name
                    return bound_method

                # Set the method on the console instance
                setattr(console_instance, method_name, make_bound_method(cmd_func))


# Global registry instance
command_registry = CommandRegistry()

# Convenience decorator
command = command_registry.register

# Import Click command support
from .click_command import command_click as _command_click


# Click command decorator that auto-registers
class command_click(_command_click):
    """Extended ClickCommand that auto-registers with the global registry."""

    def __call__(self, func):
        # Call parent to create the wrapped function
        wrapped = super().__call__(func)

        # Auto-register with the global registry
        command_registry.register(name=self.name, category=self.category)(wrapped)

        return wrapped

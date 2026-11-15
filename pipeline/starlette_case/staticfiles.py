import os
import typing
from pathlib import Path

class StaticFiles:
    def __init__(self, directory: str, follow_symlink: bool = False):
        self.directory = os.path.realpath(directory)
        self.all_directories = [self.directory]
        self.follow_symlink = follow_symlink

    def lookup_path(
            self, path: str
        ) -> typing.Tuple[str, typing.Optional[os.stat_result]]:
            for directory in self.all_directories:
                joined_path = os.path.join(directory, path)
                if self.follow_symlink:
                    full_path = os.path.abspath(joined_path)
                else:
                    full_path = os.path.realpath(joined_path)
                directory = os.path.realpath(directory)
                if not os.path.commonpath([full_path, directory]).startswith(directory):
                    continue
                try:
                    return full_path, os.stat(full_path)
                except (FileNotFoundError, NotADirectoryError):
                    continue
            return "", None

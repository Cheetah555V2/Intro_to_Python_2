import os

if os.name == "nt":
    import msvcrt

    def clear_console() -> None:
        # Use clear console command
        os.system("cls")

    def get_char() -> str:
        # Output 1 character then user type without echo and waiting for enter
        return chr(msvcrt.getch()[0])

else:
    import tty
    import termios
    import sys

    def clear_console() -> None:
        os.system("clear")

    def get_char() -> str:
        # Gets the file descriptor (an integer handle) for standard input
        file_descriptor = sys.stdin.fileno()

        # Saves the current terminal settings
        old_settings = termios.tcgetattr(file_descriptor)

        # Puts the terminal in raw mode (No echo)
        tty.setraw(file_descriptor)

        # Reads 1 character from the terminal
        character = sys.stdin.read(1)

        # Restores the original terminal settings
        termios.tcsetattr(file_descriptor, termios.TCSADRAIN, old_settings)

        # return character
        return character
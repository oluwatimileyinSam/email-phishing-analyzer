import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def path_in_app(name):
    return os.path.join(BASE_DIR, name)
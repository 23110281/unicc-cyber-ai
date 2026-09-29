"""
Test setup (pytest reads this file automatically, before any test).

The tests must behave the same on every computer, so they ignore the personal
.env settings file. (Settings still come from real environment variables.)
"""
import os

os.environ["LOAD_DOTENV"] = "0"

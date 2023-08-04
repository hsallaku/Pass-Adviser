import os
import requests
import urllib.parse

from flask import redirect, render_template, request, session
from functools import wraps

import sqlite3
connection = sqlite3.connect('passadviser.db', check_same_thread=False)
db = connection.cursor()

def apology(message, code=400):
    """Render message as an apology to user."""
    return render_template("apology.html", message=message, code=code)

def passwords():

    rows = db.execute("SELECT * FROM keychain WHERE user_id = :user",
                      {"user":session["user_id"]})

    # pass a list of lists to the template page, template is going to iterate it to extract the data into a table
    passwords = []
    for row in rows:

        # create a list with all the info about the password and append it to a list of every password
        passwords.append(list((row[1], row[2], row[3])))

    return passwords

def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function
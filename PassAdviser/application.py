import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, passwords

app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///passadviser.db")

@app.route("/")
@login_required
def index():
    """home page"""
    return render_template("index.html")


@app.route("/generator")
@login_required
def generator():
    """password generator"""
    return render_template("generator.html")


@app.route("/keychain", methods=["GET", "POST"])
@login_required
def keychain():
    """password storing feature"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # User reached via POST via add button
        if request.form['submit_button'] == "add-pass":

            if not request.form.get("pass_description"):
                return apology("must provide password description", 403)

            if not request.form.get("pass_value"):
                return apology("must provide password", 403)

            desc = request.form.get("pass_description")
            value = request.form.get("pass_value")
            db.execute("INSERT INTO keychain (user_id, pass_description, pass_value) VALUES (:user, :desc, :value)",
                user=session["user_id"], desc=desc, value=value)

            flash("Added!")
            return render_template("keychain.html", passwords=passwords())

        # User reached via POST via remove button
        elif request.form['submit_button'] == "remove-pass":

            if not request.form.get("pass_id"):
                return apology("must provide password ID", 403)

            # Query database for ID
            rows = db.execute("SELECT * FROM keychain WHERE pass_id = :pass_id",
                              pass_id=request.form.get("pass_id"))

            # Ensure ID exists
            if len(rows) != 1:
                return apology("ID was not found.", 403)

            db.execute("DELETE FROM keychain WHERE pass_id = :pass_id",
                        pass_id=request.form.get("pass_id"))

            flash("Removed!")
            return render_template("keychain.html", passwords=passwords())

    else:

        # redirect user to index page
        return render_template("keychain.html", passwords=passwords())


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure email was submitted
        if not request.form.get("email"):
            return apology("must provide email", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for email
        rows = db.execute("SELECT * FROM users WHERE email = :email",
                          email=request.form.get("email"))

        # Ensure email exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid email and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route('/register', methods=['GET','POST'])
def register():
    """register user to db"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure email was submitted
        if not request.form.get("email"):
            return apology("must provide email", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Ensure confirm password is correct
        elif request.form.get("password") != request.form.get("confirm-password"):
            return apology("The passwords don't match", 403)

        # Query database for email if already exists
        elif db.execute("SELECT * FROM users WHERE email = :email",
            email=request.form.get("email")):
            return apology("Email already taken", 403)

        # Insert user and hash of the password into the table
        db.execute("INSERT INTO users(email, hash) VALUES (:email, :hash)",
            email=request.form.get("email"), hash=generate_password_hash(request.form.get("password")))

        # Query database for email
        rows = db.execute("SELECT * FROM users WHERE email = :email",
            email=request.form.get("email"))

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)


if __name__ == "__main__":
    app.run(debug=True)

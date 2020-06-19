import base64
import io
from time import sleep
from os import listdir
from os.path import isfile

from flask import Flask, request, render_template, redirect, abort, g, make_response, send_from_directory, jsonify
from flask_mail import Mail, Message
from configparser import ConfigParser
import secrets
import hashlib
import re
import psycopg2, psycopg2.extras
from PIL import Image
from captcha_gen import generate_captcha

app = Flask(__name__)
app.config.from_pyfile('flask.cfg', silent=True)
mail = Mail(app)

db_conf = {}
parser = ConfigParser()
parser.read('postgres.cfg')
params = parser.items('postgresql')
for param in params:
    db_conf[param[0]] = param[1]


def create_session_authenticated(user_id):
    sid = secrets.token_hex(32)

    connection = get_db()
    c = connection.cursor()
    # TODO could generate an existing sid again and replace is not really an option here
    c.execute("INSERT INTO sessions VALUES (default, %(sid)s, (SELECT NOW() + interval '1 hour'), %(user_id)s);",
              {"sid": sid, "user_id": user_id})
    connection.commit()

    return sid, 3600  # 1 hour = 3600 seconds


def remove_session(session_id):
    connection = get_db()
    c = connection.cursor()
    c.execute("DELETE FROM sessions WHERE session_id = %(sid)s;", {"sid": session_id})
    connection.commit()

    return "", 0  # 0 seconds


@app.before_request
def remove_entries_expired():
    connection = get_db()
    c = connection.cursor()
    c.execute("DELETE FROM sessions WHERE expires_after < (SELECT NOW());")
    c.execute("DELETE FROM tokens_mail WHERE expires_after < (SELECT NOW());")
    c.execute("DELETE FROM tokens_password WHERE expires_after < (SELECT NOW());")
    c.execute("DELETE FROM tokens_captcha WHERE expires_after < (SELECT NOW());")
    connection.commit()


def create_user(username, password, team_name, country, university):
    salt = secrets.token_hex(32)

    h = hashlib.sha512()
    h.update(str.encode(salt))
    h.update(str.encode(password))
    user_hash = h.hexdigest()

    connection = get_db()
    c = connection.cursor()
    try:
        c.execute(
            "INSERT INTO users VALUES (default, %(username)s, %(salt)s, %(hash)s, %(team_name)s, %(country)s, \
            %(university)s, %(mail_verified)s, %(active)s);",
            {"username": username, "salt": salt, "hash": user_hash, "team_name": team_name, "country": country,
             "university": university, "mail_verified": False, "active": True})
    except psycopg2.errors.UniqueViolation as ex:  # username, team_name already exists
        connection.rollback()  # rollback to allow further db usage
        return 0

    connection.commit()

    c.execute("SELECT id FROM users WHERE username = %(username)s;", {"username": username})
    return c.fetchone()[0]  # fetchone() returns a tuple: (<user_id>, )


@app.after_request
def update_session_cookie(response):
    session = get_session(request)

    if not session is None:
        response.set_cookie(key="session", value=session[0], max_age=session[1], httponly=True)

    return response


def get_session(request):
    session_cookie = request.cookies.get("session")
    if session_cookie is None:
        return None

    connection = get_db()
    c = connection.cursor()

    # reset expires_after to initial value
    c.execute("UPDATE sessions SET expires_after = (SELECT NOW() + interval '1 hour') \
              WHERE session_id = %(sid)s;", {"sid": session_cookie})
    connection.commit()

    # max_age = 3600 seconds = 1 hour
    c.execute("SELECT session_id, 3600 as max_age, user_id FROM sessions \
              WHERE session_id = %(sid)s;",
              {"sid": session_cookie})
    return c.fetchone()


def auth(user_id, password):
    connection = get_db()
    c = connection.cursor()
    c.execute("SELECT salt, hash FROM users WHERE id = %(user_id)s;", {"user_id": user_id})
    r = c.fetchone()

    if r is None:
        return False  # unknown username # TODO timing attack leaks username

    salt = r[0]
    hash_db = r[1]

    h = hashlib.sha512()
    h.update(str.encode(salt))
    h.update(str.encode(password))
    hash_user = h.hexdigest()

    # reduce the risk of timing attacks by using special compare function
    # returns False on wrong username / password
    return secrets.compare_digest(hash_db, hash_user)


def generate_verify_mail_token(user_id):
    token = secrets.token_urlsafe(32)

    connection = get_db()
    c = connection.cursor()

    try:
        c.execute("INSERT INTO tokens_mail VALUES (default, %(token)s, (SELECT NOW() + interval '1 day'), %(user_id)s) \
        ON CONFLICT (user_id) DO UPDATE SET (token, expires_after) = (EXCLUDED.token, EXCLUDED.expires_after);",
                  {"token": token, "user_id": user_id})
    # if we get the same token twice, try another one
    except psycopg2.errors.UniqueViolation:
        connection.rollback()
        token = secrets.token_urlsafe(32)
        c.execute("INSERT INTO tokens_mail VALUES (default, %(token)s, (SELECT NOW() + interval '1 day'), %(user_id)s) \
                ON CONFLICT (user_id) DO UPDATE SET (token, expires_after) = (EXCLUDED.token, EXCLUDED.expires_after);",
                  {"token": token, "user_id": user_id})
    finally:
        connection.commit()

    return token


def generate_reset_password_token(user_id):
    token = secrets.token_urlsafe(32)

    connection = get_db()
    c = connection.cursor()

    try:
        c.execute("INSERT INTO tokens_password VALUES (default, %(token)s, (SELECT NOW() + interval '1 day'), %(user_id)s) \
    ON CONFLICT (user_id) DO UPDATE SET (token, expires_after) = (EXCLUDED.token, EXCLUDED.expires_after);",
                  {"token": token, "user_id": user_id})
    # if we get the same token twice, try another one
    except psycopg2.errors.UniqueViolation:
        connection.rollback()
        token = secrets.token_urlsafe(32)
        c.execute("INSERT INTO tokens_password VALUES (default, %(token)s, (SELECT NOW() + interval '1 day'), %(user_id)s) \
            ON CONFLICT (user_id) DO UPDATE SET (token, expires_after) = (EXCLUDED.token, EXCLUDED.expires_after);",
                  {"token": token, "user_id": user_id})
    finally:
        connection.commit()

    return token


def verify_mail(token):
    # get user_id from token
    connection = get_db()
    c = connection.cursor()
    c.execute("SELECT user_id FROM tokens_mail WHERE token = %(token)s AND expires_after >= (SELECT NOW());",
              {"token": token})
    user_id = c.fetchone()

    # fail if wrong token
    if user_id is None:
        return False

    # set mail verified and remove token
    c.execute("UPDATE users SET mail_verified = %(verified)s WHERE id = %(user_id)s;",
              {"verified": True, "user_id": user_id})
    c.execute("DELETE FROM tokens_mail WHERE token = %(token)s;", {"token": token})
    connection.commit()

    return True


def invalidate_email(user_id):
    connection = get_db()
    c = connection.cursor()
    c.execute("UPDATE users SET mail_verified = %(verified)s WHERE id = %(user_id)s;",
              {"verified": False, "user_id": user_id})
    connection.commit()


def get_team_data(user_id):
    connection = get_db()
    c = connection.cursor()
    c.execute("SELECT team_name, country, university, username FROM users WHERE id = %(user_id)s;", {"user_id": user_id})
    return c.fetchone()

footer = "Kind regards, \n" + \
         "ENOWARS \n \n" + \
         "https://enowars.com \n" + \
         "#ENOWARS on freenode\n" + \
         "https://twitter.com/enoflag"

footer_html = "<p>Kind regards, <br>" + \
              "ENOWARS <br> <br>" + \
              "<a href=\"https://enowars.com\"> enowars.com</a> <br>" + \
              "<a href=\"https://twitter.com/enoflag\">twitter.com/enoflag</a><br>" + \
              "<a href=\"https://webchat.freenode.net/\">#ENOWARS on freenode</a></p>"


def send_reset_mail_to(username):
    connection = get_db()
    c = connection.cursor()
    c.execute("SELECT id FROM users WHERE username = %(username)s;", {"username": username})
    r = c.fetchone()

    if r is None:
        return False  # unknown user

    token = generate_reset_password_token(r[0])

    reset_pw = "Hello Team, \n" + \
               "you receive this email because a password reset on https://enowars.com was requested. \n" + \
               "Please open this link to reset your ENOWARS 4 account password: {}/reset.html?token={} .\n".format(
                   app.config['APP_URL'], token) + \
               "If you did not request a new password, please ignore this email.\n \n"

    reset_pw_html = "<p>Hello Team, <br>" + \
                    "you receive this email because a password reset on <a href=\"https://enowars.com\">enowars.com</a> was requested. <br>" + \
                    "Please open this link to reset your ENOWARS 4 account password: <a href=\"{}/reset.html?token={}\">Reset Password</a> .<br>".format(
                        app.config['APP_URL'], token) + \
                    "If you did not request a new password, please ignore this email.<br></p>\n"

    msg = Message(body=reset_pw + footer,
                  subject="Reset Your ENOWARS 4 Account Password",
                  sender="mail@enowars.com",
                  recipients=[username],
                  html=reset_pw_html + footer_html)
    try:
        mail.send(msg)
    except Exception as ex:
        print(ex)
        return False

    return True


def send_activate_mail_to(user_id, username):
    token = generate_verify_mail_token(user_id)

    activate = "Hello Team, \n" + \
               "you receive this email because you created an account on https://enowars.com. \n" + \
               "Please open this link to activate your ENOWARS 4 account: {}/verify.html?token={} .\n".format(app.config['APP_URL'], token) + \
               "If you did not create an account, please ignore this email.\n \n"

    activate_html = "<p>Hello Team, <br>" + \
                    "you receive this email because you created an account on <a href=\"https://enowars.com\">enowars.com</a>. <br>" + \
                    "Please open this link to activate your ENOWARS 4 account: <a href=\"{}/verify.html?token={}\">Activate Account</a> .<br>".format(app.config['APP_URL'], token) + \
                    "If you did not create an account, please ignore this email.<br></p>\n"

    msg = Message(body=activate + footer,
                  subject="Activate Your ENOWARS 4 Account",
                  sender="mail@enowars.com",
                  recipients=[username],
                  html=activate_html + footer_html)
    try:
        mail.send(msg)
    except Exception as ex:
        print(ex)
        return

    return


def verify_reset_password_token(token):
    connection = get_db()
    c = connection.cursor()
    # TODO timing attack? # TODO JOIN necessary as relational integrity should be secure anyway?
    c.execute("SELECT user_id FROM tokens_password JOIN users on tokens_password.user_id = users.id WHERE \
              token = %(token)s AND expires_after >= (SELECT NOW());",
              {"token": token})
    user_id = c.fetchone()

    if user_id is None:
        return None

    return user_id[0]  # fetchone() returns a tuple: (<user_id>, )


def change_password_and_logout(user_id, password_new):
    salt = secrets.token_hex(32)

    h = hashlib.sha512()
    h.update(str.encode(salt))
    h.update(str.encode(password_new))
    hash_new = h.hexdigest()

    connection = get_db()
    c = connection.cursor()
    c.execute("UPDATE users SET salt = %(salt)s, hash = %(hash)s WHERE id = %(user_id)s;",
              {"salt": salt, "hash": hash_new, "user_id": user_id})
    c.execute("DELETE FROM sessions WHERE user_id = %(user_id)s;", {"user_id": user_id})
    connection.commit()


def remove_reset_password_token(token):
    connection = get_db()
    c = connection.cursor()
    c.execute("DELETE FROM tokens_password WHERE token = %(token)s;", {"token": token})
    connection.commit()


def login(username, password):
    connection = get_db()
    c = connection.cursor()
    c.execute("SELECT id FROM users WHERE username = %(username)s;", {"username": username})
    user_id = c.fetchone()

    if user_id is None:
        return None

    if auth(user_id[0], password):
        return create_session_authenticated(user_id[0])
    return None


def edit_user(user_id, email_provided, team_name_provided, country_provided, university_provided):
    connection = get_db()
    c = connection.cursor()
    try:
        c.execute(
            "UPDATE users SET username=(%(username)s), team_name=(%(team_name)s), country=(%(country)s), university=(%(university)s)"
            "WHERE id=(%(user_id)s);", {"user_id": user_id,
                                        "username": email_provided,
                                        "team_name": team_name_provided,
                                        "university": university_provided,
                                        "country": country_provided})  # TODO ( ) needed?
    except psycopg2.errors.UniqueViolation as ex:  # username or team_name already exists
        connection.rollback()  # rollback to allow further db usage
        return False  # indicate error

    connection.commit()
    return True


def is_mail_verified(user_id):
    connection = get_db()
    c = connection.cursor()
    c.execute("SELECT mail_verified FROM users WHERE id = %(user_id)s;", {"user_id": user_id})
    verified = c.fetchone()

    if verified is None:
        return False

    return verified[0]  # fetchone() returns a tuple: (<verified>, )


def is_active_account(user_id):
    connection = get_db()
    c = connection.cursor()
    c.execute("SELECT active FROM users WHERE id = %(user_id)s;", {"user_id": user_id})
    is_active = c.fetchone()

    if is_active is None:
        return False

    return is_active[0]  # fetchone() returns a tuple: (<is_active>, )


def store_img(user_id, img_data, file_type):
    connection = get_db()
    c = connection.cursor()

    c.execute("SELECT token FROM images WHERE user_id = %(user_id)s;", {"user_id": user_id})
    token = c.fetchone()

    if token is None:
        # this user uploads his initial image and don't replaces his old image so we need some unique token

        while True:  # TODO improve, timeout?
            token = secrets.token_urlsafe(32)

            # check if this generated token is unique
            c.execute("SELECT count(*) FROM images WHERE token = %(token)s;", {"token": token})
            used = c.fetchone()[0]

            if not used:
                break
    else:
        token = token[0]  # fetchone returns a tuple: (token, )

    c.execute("INSERT INTO images VALUES (DEFAULT, %(token)s, %(user_id)s, %(type)s, %(img_data)s) \
    ON CONFLICT (user_id) DO UPDATE SET (type, data) = (%(type)s, %(img_data)s);",
              {"token": token, "user_id": user_id, "type": file_type, "img_data": img_data})
    connection.commit()


def get_img_token(user_id):
    connection = get_db()
    c = connection.cursor()
    c.execute("SELECT token FROM images WHERE user_id = %(user_id)s;", {"user_id": user_id})
    result = c.fetchone()

    if result is None:
        return None

    return result[0]


def get_users():
    connection = get_db()
    c = connection.cursor(cursor_factory=psycopg2.extras.DictCursor)
    c.execute(
        "SELECT users.id, users.team_name, users.university, countries.code, countries.name, images.token FROM users \
            JOIN countries ON countries.code = users.country \
            LEFT JOIN images on images.user_id = users.id \
            WHERE users.mail_verified AND users.active \
            ORDER BY users.id;")
    users = c.fetchall()

    return users


def get_user_by_id(user_id):
    connection = get_db()
    c = connection.cursor(cursor_factory=psycopg2.extras.DictCursor)
    c.execute(
        "SELECT id, username, team_name, country, university, mail_verified, active FROM users WHERE id = %(user_id)s;",
        {"user_id": user_id})
    user = c.fetchone()

    return user


def get_countries(request):
    connection = get_db()
    c = connection.cursor(cursor_factory=psycopg2.extras.DictCursor)
    c.execute("SELECT code, name FROM countries;")
    countries = c.fetchall()

    return countries


def get_img(token):
    if token is None:
        return None

    connection = get_db()
    c = connection.cursor()
    c.execute("SELECT data, type FROM images WHERE token = %(token)s;", {"token": token})
    result = c.fetchone()

    return result


def generate_captcha_n_save_token():
    text, buffer = generate_captcha()

    # the html contains utf-8, but the image still contains bytes in base64 encoding
    captcha_base64 = base64.b64encode(buffer.getbuffer()).decode("utf-8")
    buffer.close()

    token = secrets.token_hex(32)

    connection = get_db()
    c = connection.cursor()
    # TODO could generate an existing token again and replace is not really an option here
    c.execute(
        "INSERT INTO tokens_captcha VALUES (default, %(token)s, (SELECT NOW() + interval '5 minutes'), %(text)s);",
        {"token": token, "text": text})
    connection.commit()

    return token, captcha_base64


# can't use flask global connect_db here because it is not a flask context yet
def init_db():
    tries = 0
    while tries < 5:
        try:
            connection = psycopg2.connect(**db_conf)
            cursor = connection.cursor()
            break
        except (Exception, psycopg2.Error) as e:
            print(f"Error connection to db: {e}")
        tries += 1
        sleep(3)
    if tries == 5:
        print("Couldn't connection to db")
        exit()


    try:
        c = connection.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS users (id SERIAL UNIQUE, username TEXT NOT NULL UNIQUE, salt TEXT NOT NULL, hash TEXT NOT NULL, \
                        team_name TEXT NOT NULL UNIQUE, country TEXT, university TEXT, \
                        mail_verified BOOLEAN NOT NULL, active BOOLEAN NOT NULL, PRIMARY KEY(username));")
        c.execute(
            "CREATE TABLE IF NOT EXISTS sessions (id SERIAL, session_id TEXT NOT NULL UNIQUE, expires_after TIMESTAMP NOT NULL, \
            user_id INTEGER REFERENCES users(id), PRIMARY KEY(session_id));")
        c.execute(
            "CREATE TABLE IF NOT EXISTS tokens_mail (id SERIAL, token TEXT NOT NULL UNIQUE, expires_after TIMESTAMP NOT NULL, \
            user_id INTEGER REFERENCES users(id) UNIQUE, PRIMARY KEY(token));")
        c.execute(
            "CREATE TABLE IF NOT EXISTS tokens_password (id SERIAL, token TEXT NOT NULL UNIQUE, expires_after TIMESTAMP NOT NULL, \
            user_id INTEGER REFERENCES users(id) UNIQUE, PRIMARY KEY(token));")
        c.execute(
            "CREATE TABLE IF NOT EXISTS images (id SERIAL, token TEXT NOT NULL UNIQUE, user_id INTEGER REFERENCES users(id) UNIQUE, \
            type TEXT NOT NULL, data BYTEA NOT NULL, PRIMARY KEY(token));")
        c.execute(
            "CREATE TABLE IF NOT EXISTS tokens_captcha (id SERIAL, token TEXT NOT NULL UNIQUE, expires_after TIMESTAMP NOT NULL, \
            text TEXT NOT NULL, PRIMARY KEY(token));")
        connection.commit()

    except (Exception, psycopg2.Error) as error:
        print("Error while connecting to PostgreSQL", error)
    finally:
        # closing database connection.
        if (connection):
            cursor.close()
            connection.close()
            print("PostgreSQL connection is closed")


def connect_db():
    """Connects to the specific database."""
    connection = psycopg2.connect(**db_conf)
    return connection


def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    if not hasattr(g, 'postgres_db'):
        g.postgres_db = connect_db()
    return g.postgres_db


@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    if hasattr(g, 'postgres_db'):
        g.postgres_db.close()


def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)


def is_valid_password(password):
    return re.match(r'[A-Za-z0-9@#$%^&+=]{8,265}', password)


def is_valid_country(country_code):
    connection = get_db()
    c = connection.cursor()
    c.execute("SELECT id FROM countries WHERE code = %(code)s;", {"code": country_code})
    return c.fetchone() is not None


def is_valid_university(university):
    if len(university) > 70:
        return False
    else:
        return True


def is_valid_captcha(captcha_provided, token_provided):
    if len(token_provided) == 0:
        return False

    connection = get_db()
    c = connection.cursor()
    c.execute("SELECT text FROM tokens_captcha WHERE token = %(token)s;", {"token": token_provided})
    text = c.fetchone()

    if text is None:
        return False

    if captcha_provided == text[0]:
        c.execute("DELETE FROM tokens_captcha WHERE token = %(token)s;", {"token": token_provided})
        connection.commit()

        return True
    else:
        return False


@app.route("/index.html")
def page_index():
    session = get_session(request)

    return render_template("index.html",
                           session=session,
                           registration_disabled=app.config['REGISTRATION_DISABLED'])


@app.route("/legal.html")
def page_legal():
    session = get_session(request)

    return render_template("legal.html",
                           session=session,
                           registration_disabled=app.config['REGISTRATION_DISABLED'])


@app.route("/login.html", methods=['GET', 'POST'])
def page_login():
    # redirect if user is already logged in
    if get_session(request):
        return redirect("edit.html")

    if request.method == "POST":
        try:
            email_provided = request.form["email"]
            password_provided = request.form["password"]
        except KeyError:
            abort(400)

        # TODO not distinguishing between invalid mail and wrong password could be more secure
        if not is_valid_email(email_provided):
            return render_template("login.html",
                                   msg="E-Mail should be a valid E-Mail address",
                                   msg_type="error",
                                   email=email_provided,
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])

        if not is_valid_password(password_provided):
            return render_template("login.html",
                                   msg="Wrong username / password",
                                   msg_type="error",
                                   email=email_provided,
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])

        result = login(email_provided, password_provided)

        if result is None:
            return render_template("login.html",
                                   msg="Wrong username / password",
                                   msg_type="error",
                                   email=email_provided,
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])

        # redirect on successful login
        response = redirect("edit.html")
        response.set_cookie(key="session", value=result[0],
                            max_age=result[1], httponly=True)
        return response
    else:
        return render_template("login.html",
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])


@app.route("/logout.html", methods=['POST'])
def page_logout():
    session = get_session(request)

    # redirect if user is not logged in
    if session is None:
        return redirect("login.html")

    result = remove_session(session[0])

    # redirect on successful logout
    response = redirect("index.html")

    # as the session is None now the cookie must be set (expired and to an empty string) manually
    response.set_cookie(key="session", value=result[0], max_age=result[1], httponly=True)
    return response


# noinspection PyUnboundLocalVariable
@app.route("/register.html", methods=['GET', 'POST'])
def page_register():
    # redirect if user is already logged in
    if get_session(request):
        return redirect("edit.html")

    countries = get_countries(request)

    if request.method == "POST":
        if app.config['REGISTRATION_DISABLED']:
            abort(400)
        try:
            email_provided = request.form["email"]
            password_provided = request.form["password"]
            team_name_provided = request.form["team_name"]
            country_provided = request.form["country_code"]
            university_provided = request.form.get("university")  # default: None
            captcha_provided = request.form["captcha"]
            captcha_token_provided = request.form["captcha_token"]
        except KeyError:
            abort(400)

        if not is_valid_email(email_provided):
            token, captcha = generate_captcha_n_save_token()
            return render_template("register.html",
                                   countries=countries,
                                   msg="E-Mail is not a valid E-Mail address",
                                   msg_type="error",
                                   email=email_provided,
                                   team_name=team_name_provided,
                                   country=country_provided,
                                   university=university_provided,
                                   captcha=captcha,
                                   captcha_token=token,
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])

        if len(password_provided) < 8 or len(password_provided) > 256:
            token, captcha = generate_captcha_n_save_token()
            return render_template("register.html",
                                   countries=countries,
                                   msg="Password should be between 8 and 256 characters long",
                                   msg_type="error",
                                   email=email_provided,
                                   team_name=team_name_provided,
                                   country=country_provided,
                                   university=university_provided,
                                   captcha=captcha,
                                   captcha_token=token,
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])

        if not is_valid_password(password_provided):
            token, captcha = generate_captcha_n_save_token()
            return render_template("register.html",
                                   countries=countries,
                                   msg="Password can only include the following characters: A-Z, a-z, 0-9, @#$%^&+=",
                                   msg_type="error",
                                   email=email_provided,
                                   team_name=team_name_provided,
                                   country=country_provided,
                                   university=university_provided,
                                   captcha=captcha,
                                   captcha_token=token,
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])

        if len(team_name_provided) < 4 or len(team_name_provided) > 20:
            token, captcha = generate_captcha_n_save_token()
            return render_template("register.html",
                                   countries=countries,
                                   msg="Team Name must be between 4 and 20 characters long",
                                   msg_type="error",
                                   email=email_provided,
                                   team_name=team_name_provided,
                                   country=country_provided,
                                   university=university_provided,
                                   captcha=captcha,
                                   captcha_token=token,
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])

        if not is_valid_country(country_provided):
            token, captcha = generate_captcha_n_save_token()
            return render_template("register.html",
                                   countries=countries,
                                   msg="Country code is not valid. Plz don't hack us.",
                                   msg_type="error",
                                   email=email_provided,
                                   team_name=team_name_provided,
                                   country=country_provided,
                                   university=university_provided,
                                   captcha=captcha,
                                   captcha_token=token,
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])

        if not is_valid_university(university_provided):
            token, captcha = generate_captcha_n_save_token()
            return render_template("register.html",
                                   countries=countries,
                                   msg="University cannot have more than 70 characters.",
                                   msg_type="error",
                                   email=email_provided,
                                   team_name=team_name_provided,
                                   country=country_provided,
                                   university=university_provided,
                                   captcha=captcha,
                                   captcha_token=token,
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])

        if not is_valid_captcha(captcha_provided, captcha_token_provided):
            token, captcha = generate_captcha_n_save_token()
            return render_template("register.html",
                                   countries=countries,
                                   msg="CAPTCHA not solved correctly",
                                   msg_type="error",
                                   email=email_provided,
                                   team_name=team_name_provided,
                                   country=country_provided,
                                   university=university_provided,
                                   captcha=captcha,
                                   captcha_token=token,
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])

        user_id = create_user(email_provided, password_provided, team_name_provided, country_provided,
                              university_provided)

        if not user_id:
            token, captcha = generate_captcha_n_save_token()
            return render_template("register.html",
                                   countries=countries,
                                   msg="Email or Team already exists",
                                   msg_type="error",
                                   email=email_provided,
                                   team_name=team_name_provided,
                                   country=country_provided,
                                   university=university_provided,
                                   captcha=captcha,
                                   captcha_token=token,
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])

        send_activate_mail_to(user_id, email_provided)

        # TODO POST-REDIRECT-GET redirect to edit.html?
        return render_template("login.html", msg="Account created. Activation mail sent.", msg_type="success",
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])
    else:
        # place captcha image directly in the html so no storage is required
        token, captcha = generate_captcha_n_save_token()
        return render_template("register.html",
                               countries=countries,
                               captcha=captcha,
                               captcha_token=token,
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])


@app.route("/verify.html", methods=['GET'])
def page_verify_mail():
    session = get_session(request)
    countries = get_countries(request)

    # verified sessions are good
    if session and is_mail_verified(session[2]):
        print('verified')
        return render_template("edit.html",
                               session=session,
                               countries=countries,
                               msg="Mail already verified",
                               msg_type="success",
                               logo=get_img_token(session[2]),
                               verified=is_mail_verified(session[2]),
                               active=is_active_account(session[2]),
                               team_data=get_team_data(session[2]),
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])

    try:
        token = request.args["token"]
    except KeyError:
        print('key error')
        if session:
            # unverified session without token -> send new mail
            user = get_user_by_id(session[2])
            send_activate_mail_to(session[2], user["username"])
            return render_template("edit.html",
                                   session=session,
                                   countries=countries,
                                   msg="Another activation mail send.",
                                   msg_type="info",
                                   logo=get_img_token(session[2]),
                                   verified=is_mail_verified(session[2]),
                                   active=is_active_account(session[2]),
                                   team_data=get_team_data(session[2]),
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])
        else:
            # no session no token -> redirect
            return redirect("login.html")
    # try to verify with token
    success = verify_mail(token)

    if success:
        if session:
            return render_template("edit.html",
                                   session=session,
                                   countries=countries,
                                   msg="Mail verified. Account activated.",
                                   msg_type="success",
                                   logo=get_img_token(session[2]),
                                   verified=is_mail_verified(session[2]),
                                   active=is_active_account(session[2]),
                                   team_data=get_team_data(session[2]),
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])
        return render_template("login.html",
                               msg="Mail verified. Account activated.",
                               msg_type="success",
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])

    if session:
        return render_template("edit.html",
                               session=session,
                               countries=countries,
                               msg="Wrong token.",
                               msg_type="error",
                               logo=get_img_token(session[2]),
                               verified=is_mail_verified(session[2]),
                               active=is_active_account(session[2]),
                               team_data=get_team_data(session[2]),
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])
    return render_template("login.html",
                           msg="Wrong token.",
                           msg_type="error",
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])


@app.route("/reset.html", methods=['GET', 'POST'])
def page_reset_password():
    # redirect if user is already logged in
    if get_session(request):
        return redirect("edit.html")

    if request.method == "POST":
        token = request.args.get("token")  # some secrets.token_urlsafe(32)

        if token is None:
            try:
                email_provided = request.form["email"]
            except KeyError:
                abort(400)

            if not is_valid_email(email_provided):
                return render_template("reset.html",
                                       msg="E-Mail is not a valid E-Mail adress",
                                       msg_type="error",
                                       email=email_provided,
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])

            result = send_reset_mail_to(email_provided)

            if not result:
                return render_template("reset.html",
                                       msg="Unknown email",
                                       msg_type="error",
                                       email=email_provided,
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])

            return render_template("login.html",
                                   msg="Mail send",
                                   msg_type="success",
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])
        else:
            # TODO validate data provided
            # token length?

            # find the email that belongs to the given token
            user_id = verify_reset_password_token(token)

            if user_id is None:
                return render_template("login.html",
                                       msg="Wrong token",
                                       msg_type="error",
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])

            try:
                password_provided = request.form["password"]
            except KeyError:
                abort(400)

            if len(password_provided) < 8 or len(password_provided) > 256:
                return render_template("reset.html",
                                       msg="Password should be between 8 and 256 characters long",
                                       msg_type="error",
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])

            if not is_valid_password(password_provided):
                return render_template("reset.html",
                                       msg="Password can only include the following characters: A-Z, a-z, 0-9, @#$%^&+=",
                                       msg_type="error",
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])

            change_password_and_logout(user_id, password_provided)
            remove_reset_password_token(token)

            return render_template("login.html",
                                   msg="Password set. Logged out everywhere.",
                                   msg_type="success",
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])
    else:
        token = request.args.get("token")  # default: None

        if token is not None:
            # TODO validate data provided
            # token length?
            pass

        # GET without a token results in a page where users can enter their mail adress to request a password reset mail
        # GET with a token results in a page where users can enter the new password
        return render_template("reset.html", token=token,
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])


@app.route("/change-password.html", methods=['GET', 'POST'])
def page_change_password():
    session = get_session(request)

    # redirect if user is not logged in
    if not session:
        return redirect("login.html")

    if request.method == "POST":
        try:
            password_provided = request.form["password"]
            password_new_provided = request.form["password_new"]
        except KeyError:
            abort(400)

        if not auth(session[2], password_provided):
            return render_template("change-password.html",
                                   msg="Wrong password.",
                                   msg_type="error",
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])

        if len(password_new_provided) < 8 or len(password_new_provided) > 256:
            return render_template("change-password.html",
                                   msg="Password should be between 8 and 256 characters long",
                                   msg_type="error",
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])

        if not is_valid_password(password_provided):
            return render_template("change-password.html",
                                   msg="Password can only include the following characters: A-Z, a-z, 0-9, @#$%^&+=",
                                   msg_type="error",
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])

        change_password_and_logout(session[2], password_new_provided)

        # session is intentionally omitted so the user gets an logged out version of the page
        return render_template("login.html",
                               msg="Password set. Logged out everywhere.",
                               msg_type="success",
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])
    else:
        return render_template("change-password.html", session=session,
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])


@app.route("/edit.html", methods=['GET', 'POST'])
def page_edit():
    session = get_session(request)

    # redirect if user is not logged in
    if not session:
        return redirect("login.html")

    countries = get_countries(request)

    if request.method == "POST":
        try:
            email_provided = request.form["email"]
            team_name_provided = request.form["team_name"]
            country_provided = request.form["country_code"]
            university_provided = request.form.get("university")  # default: None
        except KeyError:
            abort(400)

        if not is_valid_email(email_provided):
            return render_template("edit.html",
                                   session=session,
                                   countries=countries,
                                   msg="E-mail is not a valid e-mail-address",
                                   msg_type="error",
                                   logo=get_img_token(session[2]),
                                   verified=is_mail_verified(session[2]),
                                   active=is_active_account(session[2]),
                                   team_data=get_team_data(session[2]))

        if len(team_name_provided) < 4 or len(team_name_provided) > 20:
            return render_template("edit.html",
                                   session=session,
                                   countries=countries,
                                   msg="Team name must be between 4 and 20 characters long",
                                   msg_type="error",
                                   logo=get_img_token(session[2]),
                                   verified=is_mail_verified(session[2]),
                                   active=is_active_account(session[2]),
                                   team_data=get_team_data(session[2]))

        if not is_valid_country(country_provided):
            return render_template("edit.html",
                                   session=session,
                                   countries=countries,
                                   msg="Country code is not valid. Plz don't hack us.",
                                   msg_type="error",
                                   logo=get_img_token(session[2]),
                                   verified=is_mail_verified(session[2]),
                                   active=is_active_account(session[2]),
                                   team_data=get_team_data(session[2]))

        if not is_valid_university(university_provided):
            return render_template("edit.html",
                                   session=session,
                                   countries=countries,
                                   msg="University cannot have more than 70 characters.",
                                   msg_type="error",
                                   logo=get_img_token(session[2]),
                                   verified=is_mail_verified(session[2]),
                                   active=is_active_account(session[2]),
                                   team_data=get_team_data(session[2]))

        old_team_data = get_team_data(session[2])
        success = edit_user(session[2], email_provided, team_name_provided, country_provided, university_provided)

        if not success:
            return render_template("edit.html",
                                   session=session,
                                   countries=countries,
                                   msg="E-mail-address or team name already exists",
                                   msg_type="error",
                                   logo=get_img_token(session[2]),
                                   verified=is_mail_verified(session[2]),
                                   active=is_active_account(session[2]),
                                   team_data=old_team_data)

        # mark email_verified as false if email changed
        if email_provided != old_team_data[3]:
            invalidate_email(session[2])

        return render_template("edit.html",
                               session=session,
                               countries=countries,
                               msg="Profile updated.",
                               msg_type="success",
                               logo=get_img_token(session[2]),
                               verified=is_mail_verified(session[2]),
                               active=is_active_account(session[2]),
                               team_data=get_team_data(session[2]))
    else:
        return render_template("edit.html",
                               session=session,
                               countries=countries,
                               verified=is_mail_verified(session[2]),
                               logo=get_img_token(session[2]),
                               active=is_active_account(session[2]),
                               team_data=get_team_data(session[2]))


@app.route("/downloads.html", methods=['GET'])
def page_downloads():
    session = get_session(request)

    # redirect if user is not logged in
    if not session:
        return redirect("login.html")

    files = filter(lambda f: not f.startswith('.'), listdir(app.root_path + '/files'))

    return render_template("downloads.html",
                           session=session,
                           verified=is_mail_verified(session[2]),
                           active=is_active_account(session[2]),
                           download_options={
                               'DOWNLOAD_CONFIG_ENABLED': app.config['DOWNLOAD_CONFIG_ENABLED'] and
                                                          isfile(app.root_path + '/downloads/team' + str(session[2]) + '.conf'),
                               'DOWNLOAD_KEY_ENABLED': app.config['DOWNLOAD_KEY_ENABLED'] and
                                                       isfile(app.root_path + '/downloads/vm.key')
                           },
                           files=files)


@app.route("/upload.html", methods=['POST'])
def page_img_upload():
    session = get_session(request)

    # deny if user is not logged in
    if not session:
        abort(403)

    # deny if account is not activated or mail is not verified
    if not is_mail_verified(session[2]) or not is_active_account(session[2]):
        abort(403)

    if request.content_length > (500 * 1024) or request.content_length == 0:  # max. 500 kilobyte
        abort(400)

    # validate content type of the uploading image
    if not (request.content_type == "image/png"
            or request.content_type == "image/gif"
            or request.content_type == "image/jpeg"):
        abort(400)

    try:
        im = Image.open(io.BytesIO(request.data))
    except IOError as ex:
        return make_response("Image format could not be verified. Please try an other image.", 400)

    # validate actual image format matches content type
    if request.content_type == "image/png":
        if not im.format == "PNG":
            abort(400)
    elif request.content_type == "image/gif":
        if not im.format == "GIF":
            abort(400)
    elif request.content_type == "image/jpeg":
        if not im.format == "JPEG":
            abort(400)

    # check image size
    if im.width > 480 or im.width < 20 or im.height > 480 or im.height < 20:
        return make_response("Wrong image size.", 400)

    store_img(session[2], request.data, request.content_type)

    return make_response("", 204)  # success, triggers page reload via js


@app.route("/teams.html")
def page_teams():
    session = get_session(request)

    users = get_users()
    countries = get_countries(request)

    return render_template("teams.html",
                           session=session,
                           users=users,
                           countries=countries,
                                   registration_disabled=app.config['REGISTRATION_DISABLED'])

@app.route("/network.html")
def page_network():
    session = get_session(request)
    return render_template("network.html",
                           session=session,
                           registration_disabled=app.config['REGISTRATION_DISABLED'])

@app.route("/rules.html")
def page_rules():
    session = get_session(request)
    return render_template("rules.html",
                           session=session,
                           registration_disabled=app.config['REGISTRATION_DISABLED'])

@app.route("/vms.html")
def page_vms():
    session = get_session(request)
    return render_template("vms.html",
                           session=session,
                           registration_disabled=app.config['REGISTRATION_DISABLED'])
@app.route("/faq.html")
def page_faq():
    session = get_session(request)
    return render_template("faq.html",
                           session=session,
                           registration_disabled=app.config['REGISTRATION_DISABLED'])

@app.route("/information.html")
def page_information():
    session = get_session(request)

    return render_template("information.html",
                           session=session,
                           registration_disabled=app.config['REGISTRATION_DISABLED'])

@app.route("/secret/export")
def export_teams():
    try:
        password = request.args["pw"]
    except KeyError:
        abort(404)

    if password != app.config['EXPORT_PASSWORD']:
        abort(404)

    connection = get_db()
    c = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    c.execute("SELECT users.id, users.team_name, users.university, countries.code, countries.name, images.token FROM users JOIN countries ON countries.code = users.country LEFT JOIN images on images.user_id = users.id WHERE users.mail_verified and users.active;")
    users = c.fetchall()

    # transform keys to gameengine style
    for user in users:
        user["Id"] = user.pop("id")
        user["Name"] = user.pop("team_name")
        user["TeamSubnet"] = "fd00:1337:" + str(user["Id"]) + "::"
        university = user.pop("university")
        if university:
            user["University"] = university
        else:
            user["University"] = None
        country_code = user.pop("code")
        user["Country"] = {
            "Code": country_code,
            "Name": user.pop("name"),
            "FlagUrl": request.url_root + "flags/" + country_code + ".svg"
        }
        logo_token = user.pop("token")
        if logo_token:
            user["LogoUrl"] = request.url_root + "logo?img=" + logo_token
        else:
            user["LogoUrl"] = None


    return jsonify({"Teams": users})

@app.route("/logo")
def page_img():
    try:
        token = request.args["img"]
    except KeyError:
        # bad request
        abort(400)

    img = get_img(token)

    if img is None:
        abort(404)

    response = make_response(img[0].tobytes())
    response.mimetype = img[1]

    return response


@app.route("/download")
def download():
    session = get_session(request)

    # redirect if user is not logged in
    if not session:
        return redirect("login.html")

    try:
        file = request.args["file"]
    except KeyError:
        # bad request
        abort(400)

    if file == 'vpn_config':
        filename = 'team' + str(session[2]) + '.conf'
    elif file == 'key':
        filename = 'vm.key'
    else:
        abort(404)

    return send_from_directory(app.root_path + '/downloads/', filename, as_attachment=True)


init_db()

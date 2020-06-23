from flask_mail import Mail, Message
from flask import Flask
from configparser import ConfigParser
import psycopg2, psycopg2.extras
import time

app = Flask(__name__)
app.config.from_pyfile('flask.cfg', silent=True)
mail = Mail(app)

db_conf = {}
parser = ConfigParser()
parser.read('postgres.cfg')
params = parser.items('postgresql')
for param in params:
    db_conf[param[0]] = param[1]

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

subject = "ENOWARS 3 Recap (pls give feedback!)"

text = "Hello Teams, \n" + \
"The CTF is over! Thanks a lot for participating! \n" + \
"\n" + \
"We will publish the final scoring asap on the website. \n" + \
"\n" + \
"With around 180 registered and 30 actively playing teams, we are satisfied with the competition and all your hacking skillz. \n" + \
"We hope you enjoyed it, too!\n" + \
"\n" + \
"We would really appreciate if your team could find the 5 minutes to give us some feedback [0]. (For the teams that did sign up, but did not play - what was the issue?) \n" + \
"\n" + \
"https://forms.gle/ftJbFrE1wL5EJB416\n" + \
"\n" + \
"[If you do not like Google, you can reply to this email :-)]\n" + \
"\n" + \
"Thanks a lot in advance and see you next year,\n" + \
"\n" + \
"The ENOWARS team\n" + \
"\n" + \
"[0] https://forms.gle/ftJbFrE1wL5EJB416 \n\n"

text_html = "<p>Hello Team, <br>" + \
"News from ENOWARS 3! We added a lot of information to the page and put the team router + test vm online.<br>" + \
"Sign in and check <a href=\"https://enowars.com/downloads.html\">https://enowars.com/downloads.html</a> .<br>"+ \
"Feel free to reach out to us if you have any questions.<br></p>\n"

def send_all(body, subject):
    with app.app_context():
        connection = psycopg2.connect(**db_conf)
        cursor = connection.cursor()

        c = connection.cursor(cursor_factory=psycopg2.extras.DictCursor)
        c.execute("SELECT users.username FROM users WHERE mail_verified = 't';")
        emails = c.fetchall()

        assert len(emails) > 0
        assert type(emails) == list
        x = 0
        for email in emails:
            # Note that type(email) must be list too
            msg = Message(body=body
                          subject=subject,
                          sender="mail@enowars.com",
                          recipients=email)

            try:
                mail.send(msg)
            except Exception as ex:
                print("Exception in send for team: " + email[0])
                print(ex)
            finally:
                x+=1
                print ("Team: " + email[0] + " done. "+ str(x) +" out of " + str(len(emails)))
                print("Delay because otherwise mail provider thinks I am spamming.")
                time.sleep(5)

def get_emails():
    with app.app_context():
        connection = psycopg2.connect(**db_conf)
        cursor = connection.cursor()

        c = connection.cursor(cursor_factory=psycopg2.extras.DictCursor)
        c.execute("SELECT users.username FROM users WHERE mail_verified = 't';")
        emails = c.fetchall()

        # Flatten the curv... ehh list!
        emails = [y for x in emails for y in x]
        assert len(emails) > 0
        assert type(emails) == list
        return emails

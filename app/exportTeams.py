from configparser import ConfigParser
import psycopg2, psycopg2.extras
import json, argparse, base64

db_conf = {}
parser = ConfigParser()
parser.read('postgres.cfg')
params = parser.items('postgresql')
for param in params:
    db_conf[param[0]] = param[1]


def get_users(style):


    connection = psycopg2.connect(**db_conf)
    c = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    if style == "gameengine":
        print("gameengine style")
        c.execute("SELECT users.id, users.team_name FROM users ;")
        users = c.fetchall()


        # transform keys to gameengine style
        for user in users:
            user["Id"] = user.pop("id")
            user["Name"] = user.pop("team_name")
            user["TeamSubnet"] = "fd00:1337:" + str(user["Id"]) + "::"

        return users
    elif style == "scoreboard":
        print("scoreboard style")
        c.execute("SELECT users.id, users.team_name, users.username, users.university, countries.code as country_code, countries.name as country_name, images.data as logo_b64 FROM users JOIN countries ON countries.code = users.country LEFT JOIN images on images.user_id = users.id;")
        users = c.fetchall()

        for user in users:
            user["team_subnet"] = "fd00:1337:" + str(user["id"]) + "::"
            if user["logo_b64"] is not None:
                user["logo_b64"] = (base64.b64encode(user["logo_b64"])).decode('utf-8')

        return users

    print("you have no style")
    return []

parser = argparse.ArgumentParser()
parser.add_argument("style", help="select your json style - \"gameengine\" | \"scoreboard\"")
args = parser.parse_args()
print("exporting teams to teams.json ")
f = open("teams.json", "w")
f.write(json.dumps({"Teams": get_users(args.style)}, indent=2, sort_keys=True))
f.close()
print("exporting teams done!")
# EnoTeams
CTF team registration page based on Flask, Gunicorn and Nginx.


Recommended Code Style: https://www.python.org/dev/peps/pep-0008/
## Development

	cp app/postgres.cfg.example app/postgres.cfg
	cp app/flask.cfg.example app/flask.cfg
	mkdir postgres_data
	docker-compose up -d nginx gunicorn postgres

Add `127.0.0.1 enowars.local` to your hosts.txt to access the page through enowars.local .

## Production

Postgres needs an empty data folder (we can't add that to git) therefore create the folder `postgres_data` in the root directory.

     mkdir postgres_data 

Make sure to use nginx.live.conf in Nginx Dockerfile and run `deployment_ini_letsencrypt.sh` once to create dummy certificates before nginx start.

Cronjob to set download files permission:

    */2 * * * * /bin/chmod -R 0644 /eno/enoteams/static/files/*

SQL Dump    
    
    pg_dump -d postgres -h 127.0.0.1 -p 5432 -U postgres -W dump.psql

Reset Postgres Sequenze

    ALTER SEQUENCE users_id_seq RESTART;

## Updating

    git pull
    sudo docker-compose restart gunicorn 

## Emails

To send an email to all registered teams use the script in `app/team_mail.py`  
**Before adapt the content of the script to send your actual text to the team and NOT the dummy data.**
Invoke it from within the gunicorn container:

    docker-compose exec gunicorn sh
    $python3 team_mail.py


## Team data

### Description

    id: integer,
    username: email,
    team_name: text,
    country: text,
    university: text,
    mail_verified: boolean,
    active: boolean

- `id` is a incremented number starting from `1
- `username` is an email address (`re.match(r"[^@]+@[^@]+\.[^@]+", email)`)
- `team_name` is a string (`3 < length < 20`)
- `country` is a string (`2 character, ISO 3166-1 Alpha-2 code`)
- `university` is a string (`re.match("^[A-Za-z äöüÄÖÜß]*$", university)`)
- `mail_verified` is a boolean
- `active` is a boolean

### Get the data

Get access to the host

Use secret/export?pw=*password from flask.cfg*

    http://enowars.local/secret/export?pw=test
    

## Downloads

Put all public or large files (e.g. vms) in  `/root/enoteams/static/files` and secret or small files (e.g. config files & keys) in `/root/enoteams/app/downloads/` at the registration host (enowars.com).
Use the following name scheme:

    root@localhost:~/enoteams/static/files# ls
    team_router.tar.gz
    test_vm.tar.gz
    vm.tar.gz

    root@localhost:~/enoteams/app/downloads# ls
    team1.conf
    vm.key

- Router: `team_router.tar.gz`
- Test VM: `test_vm.tar.gz`
- VM: `vm.tar.gz`
- VM Key: `vm.key`
- Wireguard Configurations: `teamX.conf` with X increasing int (team 1 will be able to download the file `team1.conf`, team 2 `team2.conf` etc.)
- OpenVPN Configurations: 'teamX.ovpn' with X increasing int (team 1 will be able to download the file `team1.conf`, team 2 `team2.conf` etc.)


Authenticated downloads can be enabled/disabled through the `flask.cfg`:
    
    DOWNLOAD_CONFIG_ENABLED=True
    DOWNLOAD_OPENVPN_CONFIG_ENABLED=True
    DOWNLOAD_KEY_ENABLED=True

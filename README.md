# Ariane Cours

This is a lightweight platform to host training sessions instructions and files for students.

All files are stored in the `upload/` folder.

There is no database, as there should not be many sessions at the same time. They are stored as JSON in `sessions.json`.

A `security.log` log file is provided: it may be consumed by fail2ban to ban offending users (better and longer than the banning already present in the code).

Also, the "validate" section in the admin page is created to use a script to automate a bash script (used in my case to create Proxmox users for exercises), and is not (yet) fully tested.

## License
Apache 2.0, see `LICENSE`.


   Copyright 2025 Maxence MOHR aka fladna9

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

## Run locally in debug mode (dev, tests)

All these commands have been tested on Debian 13. 
It should work anywhere else, as long as you provide the right python packes for the distro you are using.

```bash
apt install python3-flask python3-flaskext.wtf
flask --app app run
```

## Run in production mode

All these commands have been tested on Debian 13. 
It should work anywhere else, as long as you provide the right python packes for the distro you are using.

Copy `example.env` to `.env`, and fill it in.
`ADMIN_PASSWORD_HASH` is recommended over `ADMIN_PASSWORD`.
`SECRET_KEY` must be filled as indicated.

Create a systemd unit in `/etc/systemd/system/ariane.service`. Change `User`, `Group`, `WorkingDirectory` to fit your system.

```systemd
[Unit]
Description=Gunicorn starting Ariane project
After=network.target

[Service]
Type=notify
NotifyAccess=main
User=user
Group=user
RuntimeDirectory=gunicorn
WorkingDirectory=/home/user/Ariane-Cours
ExecStart=/usr/bin/gunicorn -w 1 -b 127.0.0.1 "app:app"
ExecReload=/bin/kill -s HUP $MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```


```bash
apt install python3-gunicorn gunicorn python3-flask python3-flaskext.wtf
systemctl daemon-reload
systemctl enable --now ariane.service
```

You should be able to see it working with curl.
```bash
curl http://127.0.0.1:8000
```

Put a `Apache2`, `HAProxy` or `Nginx` in reverse proxy in front of it, with `certbot` for a valid TLS certificate, and you should be good.

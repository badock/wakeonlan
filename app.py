from flask import Flask
import flask
from wakeonlan import send_magic_packet
import yaml
import os
from flask_login import LoginManager
from flask_login import login_required, login_user, logout_user
from flask_login import UserMixin
from urllib.parse import urlparse, urljoin
from flask import request, url_for


app = Flask(__name__)
app.secret_key = "wakeonlan_flask"
login = LoginManager(app)
login.login_view = 'login'


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc


class User(UserMixin):
    pass


def validate_login():
    return False


@login.user_loader
def load_user(userid):
    flask_login_user = User()
    flask_login_user.username = userid
    flask_login_user.id = userid
    return flask_login_user


@app.route("/login")
@app.route("/login?msg=<msg>")
def login(msg=""):
    return flask.render_template("login.html.jinja2",
                                 msg=msg)


@app.route("/logout")
def logout():
    logout_user()
    return flask.redirect(url_for("index"))


@app.route("/process_login", methods=['POST'])
def process_login():
    with open("config/config.yaml") as f:
        config = yaml.load(f)
    users = config.get("users")

    for user in users:
        if flask.request.form.get("username") == user.get("username") \
                and flask.request.form.get("password") == user.get("password"):
            # Login and validate the user.
            # user should be an instance of your `User` class
            flask_login_user = User()
            flask_login_user.username = user.get("username")
            flask_login_user.id = user.get("username")
            login_user(flask_login_user)

            flask.flash('Logged in successfully.')

            next = flask.request.args.get('next')
            # is_safe_url should check if the url is safe for redirects.
            # See http://flask.pocoo.org/snippets/62/ for an example.
            if not is_safe_url(next):
                return flask.abort(400)

            return flask.redirect(next or flask.url_for('index'))
    return flask.redirect(url_for("login", msg="You are not authorized!"))


@app.route("/home")
@app.route("/")
@login_required
def index():
    with open("config/config.yaml") as f:
        config = yaml.load(f)
    computers = config.get("computers")
    for computer_name, computer in computers.items():
        ip_address = computer.get("ip_address")
        response = os.system("ping -W 0.1 -c 1 " + ip_address)
        if response == 0:
            computer["status"] = "online"
        else:
            computer["status"] = "offline"
    return flask.render_template("homepage.html.jinja2",
                                 computers=computers)


@app.route('/action/<action>/<computer_id>')
@login_required
def perform_action(action, computer_id):
    with open("config/config.yaml") as f:
        config = yaml.load(f)
    computers_candidates = [c for c in config.get("computers").values() if c.get("id") == computer_id]
    if len(computers_candidates) == 1:
        [selected_computer] = computers_candidates
        if action == "on":
            send_magic_packet(selected_computer.get("mac_address"),
                              ip_address=selected_computer.get("broadcast_address"))
    return flask.redirect(flask.url_for("index"))


if __name__ == '__main__':
    app.run()

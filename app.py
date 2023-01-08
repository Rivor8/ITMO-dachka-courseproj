import os
import json

from flask import Flask, url_for, render_template, request
from flask_login import LoginManager, login_user, login_required, logout_user, current_user

from werkzeug.exceptions import abort
from werkzeug.utils import redirect

from data import db_session
from data.users import User
from data.stations import Station
from data.announcements import Announcement
from data.favs import Fav

import requests
from forms import *
from urllib.parse import unquote

from config import *

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    session = db_session.create_session()
    return session.query(User).get(user_id)


@app.route('/')
@app.route('/index')
def index():
    session = db_session.create_session()
    if current_user.is_authenticated:
        favs = session.query(Fav).filter(Fav.user == current_user)
        return render_template('index.html', title='Главная', favs=favs[::-1])
    else:
        return render_template('index.html', title='Главная')


@app.route('/schedule', methods=['GET', 'POST'])
def schedule():
    if request.method == "GET":
        session = db_session.create_session()
        ya_req = {
            'from': session.query(Station).filter(Station.name == request.args.get("station_from"))[0].code,
            'to': session.query(Station).filter(Station.name == request.args.get("station_to"))[0].code,
            'apikey': YA_API_KEY,
            'date': request.args.get("date_travel")
        }
        ya_resp = requests.get("https://api.rasp.yandex.net/v3.0/search/", params=ya_req)
        print(json.loads(ya_resp.text), ya_resp.text, sep="\n\n\n")
        if 'segments' in json.loads(ya_resp.text):
            return render_template('schedule.html', title='Расписание', rasp=json.loads(ya_resp.text)['segments'])
    return render_template('schedule.html', title='Расписание', rasp=[])

@app.route('/addfav', methods=['GET', 'POST'])
def addfav():
    if request.method == 'POST':
        session = db_session.create_session()
        fav = Fav()
        fav.station_from = unquote(request.form.get("station_from"))
        fav.station_to = unquote(request.form.get("station_to"))
        current_user.favs.append(fav)
        session.merge(current_user)
        session.commit()
        return "ok"
    return abort(404)



@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if form.password.data != form.password_again.data:
            return render_template('register.html', title='Регистрация',
                                   form=form,
                                   message="Пароли не совпадают")
        session = db_session.create_session()
        if session.query(User).filter(User.email == form.email.data).first():
            return render_template('register.html', title='Регистрация',
                                   form=form,
                                   message="Такой пользователь уже есть")
        user = User(
            name=form.name.data,
            email=form.email.data
        )
        user.set_password(form.password.data)
        session.add(user)
        session.commit()
        return redirect('/login')
    return render_template('register.html', title='Регистрация', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        session = db_session.create_session()
        user = session.query(User).filter(User.name == form.name.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect("/")
        return render_template('login.html',
                               message="Неправильный логин или пароль",
                               form=form)
    return render_template('login.html', title='Авторизация', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/")


def main():
    db_session.global_init("db/db.sqlite")
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)


if __name__ == '__main__':
    main()
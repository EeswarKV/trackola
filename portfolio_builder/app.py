from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
import requests
import pandas as pd
from functools import wraps
from portfolio_builder.components.dashboard.dashboard import build_pie_chart_data, build_market_cap_chart_data, build_stock_allocation_percentage_data
from urllib.parse import quote_plus, urlencode
from dotenv import find_dotenv, load_dotenv
from authlib.integrations.flask_client import OAuth
from os import environ as env
from authlib.integrations.flask_oauth2 import ResourceProtector
import ssl
ssl._create_default_https_context = ssl._create_unverified_context

app = Flask(__name__, template_folder='components',
            static_folder='components', static_url_path='/components')
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///portfolio-analysis.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app.secret_key = env.get("APP_SECRET_KEY")

oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    audidance=env.get("AUTH0_AUDIANCE"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')


class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[
                                     DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')


with app.app_context():
    # Create the tables
    db.create_all()

# decorator to check if user logged in and returns user if successful


def login_required_for_new_way(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = oauth.auth0.authorize_access_token()
        values = token['userinfo']
        print(values)
        emailValue = values['name'].strip()
        user = User.query.filter_by(
            email=emailValue).first() if emailValue else None
        print(user)
        if user is None:
            print("no user info present")
            return redirect(url_for('login'))
        return f(user, *args, **kwargs)
    return decorated_function


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        return oauth.auth0.authorize_redirect(redirect_uri=url_for("home", _external=True))
        # form = LoginForm()
        # if form.validate_on_submit():
        #     return get_user_login(form)
        # return render_template('login.html', form=form)
    except Exception as e:
        print(f"Error trying to login: {e}")
        return None


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_username = User.query.filter_by(
            username=form.username.data).first()
        existing_email = User.query.filter_by(email=form.email.data).first()
        if existing_username:
            flash('danger: Username already exists. Please choose a different username.')
            return redirect(url_for('register/register.html'))
        if existing_email:
            flash('danger: Email already exists. Please choose a different email.')
            return redirect(url_for('register/register.html'))

        hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
        user = User(email=form.email.data,
                    username=form.username.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        # Redirect to the login page
        return redirect(url_for('login/login.html'))

    return render_template('register/register.html', form=form)


@app.route('/logout')
def logout():
    try:
        session.clear()
        return redirect(
            "https://"
            + env.get("AUTH0_DOMAIN")
            + "/v2/logout?"
            + urlencode(
                {
                    "returnTo": url_for("login", _external=True),
                    "client_id": env.get("AUTH0_CLIENT_ID"),
                },
                quote_via=quote_plus,
            )
        )
    except Exception as e:
        print(f"Error trying to logout: {e}")
        return None



@app.route('/home')
def home():
    user_info = requests.get(
        'http://localhost:5001/api/user_info').json()
    return render_template('home/home.html', active_page='home',user_info=user_info)


@app.route('/dashboard')
def dashboard():
    user_info = requests.get(
        'http://localhost:5001/api/user_info').json()
    if user_info['isFundManager'] == True:
        fund_manager_data = requests.get(
        'http://localhost:5001/api/get_fund_manager_data').json()
        portfolio = {
        'Total Assets Under Management': fund_manager_data["portfolioOverview"]["totalAUM"],
        'Total Customers': fund_manager_data["portfolioOverview"]["totalCustomers"],
        'Portfolio Value': fund_manager_data["portfolioOverview"]["portfolioValue"],
        'Total Funds Available': 80000,
        }
        return render_template('dashboard/fund-manager-dashboard/dashboard.html', data=fund_manager_data, active_page='dashboard', portfolio=portfolio,user_info=user_info)
    stock_table_data = requests.get(
        'http://localhost:5001/api/stock_table_data').json()
    sector_data = build_pie_chart_data(stock_table_data)
    market_cap_data = build_market_cap_chart_data(stock_table_data)
    allocation_percentage_data = build_stock_allocation_percentage_data(
        stock_table_data)
    line_chart_data = {
        "investment_data": [
            {"date": "2023-07-25", "value": 138511.25},
            {"date": "2023-08-01", "value": 140074.25},
            {"date": "2023-08-02", "value": 142080.25},
            {"date": "2023-08-05", "value": 147800}
        ],
        "nifty50_data": [
            {"date": "2023-07-25", "value": 16000},
            {"date": "2023-08-01", "value": 16120.4},
            {"date": "2023-08-02", "value": 16222.004},
            {"date": "2023-08-05", "value": 16398.53}
        ]
    }
    investment_dates = [entry["date"]
                        for entry in line_chart_data["investment_data"]]
    investment_values = [entry["value"]
                         for entry in line_chart_data["investment_data"]]

    index_values = [entry["value"]
                    for entry in line_chart_data["nifty50_data"]]
    portfolio = {
        'Total Invested Amount': stock_table_data["summary"]["totalInvested"],
        'Total Current': stock_table_data["summary"]["currentTotal"],
        'Rate of return': stock_table_data["summary"]["totalPL"],
        'Total Funds Available': 80000,
    }
    return render_template('dashboard/dashboard.html', portfolio=portfolio, active_page='dashboard', stock_table_data=stock_table_data, sector_data=sector_data, market_cap_data=market_cap_data, allocation_percentage_data=allocation_percentage_data, investment_dates=investment_dates, investment_values=investment_values, index_values=index_values,user_info=user_info)


@app.route('/customers')
def customers():
    user_info = requests.get(
        'http://localhost:5001/api/user_info').json()
    stock_table_data = requests.get(
        'http://localhost:5001/api/stock_table_data').json()
    sector_data = build_pie_chart_data(stock_table_data)
    market_cap_data = build_market_cap_chart_data(stock_table_data)
    allocation_percentage_data = build_stock_allocation_percentage_data(
        stock_table_data)
    line_chart_data = {
        "investment_data": [
            {"date": "2023-07-25", "value": 138511.25},
            {"date": "2023-08-01", "value": 140074.25},
            {"date": "2023-08-02", "value": 142080.25},
            {"date": "2023-08-05", "value": 147800}
        ],
        "nifty50_data": [
            {"date": "2023-07-25", "value": 16000},
            {"date": "2023-08-01", "value": 16120.4},
            {"date": "2023-08-02", "value": 16222.004},
            {"date": "2023-08-05", "value": 16398.53}
        ]
    }
    investment_dates = [entry["date"]
                        for entry in line_chart_data["investment_data"]]
    investment_values = [entry["value"]
                         for entry in line_chart_data["investment_data"]]

    index_values = [entry["value"]
                    for entry in line_chart_data["nifty50_data"]]
    portfolio = {
        'Total Invested Amount': stock_table_data["summary"]["totalInvested"],
        'Total Current': stock_table_data["summary"]["currentTotal"],
        'Rate of return': stock_table_data["summary"]["totalPL"],
        'Total Funds Available': 80000,
    }
    return render_template('customers/customers.html', portfolio=portfolio, active_page='customers', stock_table_data=stock_table_data, sector_data=sector_data, market_cap_data=market_cap_data, allocation_percentage_data=allocation_percentage_data, investment_dates=investment_dates, investment_values=investment_values, index_values=index_values,user_info=user_info)


@app.route('/notifications')
def notifications():
    user_info = requests.get(
        'http://localhost:5001/api/user_info').json()
    return render_template('notifications/notifications.html', active_page='notifications',user_info=user_info)


if __name__ == '__main__':
    app.run(port=5000)

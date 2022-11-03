import collections
import bcrypt
from time import sleep
from json2html import * 
import requests, psycopg2, json
from flask import Flask, render_template, request, redirect, url_for
from wtforms import StringField, PasswordField, BooleanField, ValidationError
from wtforms.validators import InputRequired, Email, Length
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, UserMixin, login_required, login_user, login_remembered, logout_user
from flask_sqlalchemy import SQLAlchemy

# Connection to DB

conn = psycopg2.connect(database="nft_test", user = "postgres", password = "PASSWORD", host = "127.0.0.1", port = "5432")

url = "https://solana-gateway.moralis.io/nft/mainnet/{}/metadata"

headers = {
    "accept": "application/json",
    "X-API-Key": "Your own API-KEY"
}

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Mysecretkey'
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql+psycopg2://postgres:PASSWORD@localhost/nft_test"
db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class Users(UserMixin, db.Model):
    name = db.Column(db.Text, primary_key=True)
    email = db.Column(db.Text)
    password = db.Column(db.Text)

    def get_id(self):
        return (self.name)

@login_manager.user_loader
def load_user(name):
    return Users.query.filter_by(name=name).first()

class LoginForm(FlaskForm):
    def validate_password(form, password):
        user = Users.query.filter_by(name=form.username.data).first()
        if user:
            salt = bytes(user.password, 'utf-8')
            if not bcrypt.checkpw(password.data.encode('utf-8'), salt):
                raise ValidationError('Password is incorrect')

    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=4, max=15)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    def validate_username(form, username):
        user = Users.query.filter_by(name=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose another.')

    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=30)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=4, max=15)])

@app.route("/", methods=['GET', 'POST'])
def index():
    return render_template('index.html')

@app.route("/search", methods=['GET', 'POST'])
@login_required
def search():
    if request.method == 'POST':
        address = request.form.get('address')

        # Checking if the nft table exists in our database
        cur = conn.cursor()
        cur.execute("select * from information_schema.tables where table_name='nft_table'")
        nft_table_exists = bool(cur.rowcount)
        nft_exist = False
        # Checking if our table has this particular address
        if nft_table_exists:
            cur.execute("SELECT mint FROM nft_table WHERE mint = %s", (address,))
            nft_exist = (cur.fetchone() is not None)   

        # If this address is already in our table, let's try to display it
        if nft_exist:

            # The code below converts our record from the database to JSON, similar to what we get from Moralis API
            cur.execute('''SELECT * FROM nft_table LEFT JOIN multiplex_table USING(metaplex_id) 
                LEFT JOIN owners ON nft_table.mint = owners.nft_address WHERE mint=%s''', (address,))
            rows = cur.fetchall()

            owners = []
            for owner in rows:
                o = collections.OrderedDict()
                o["address"] = owner[11]
                o["share"] = owner[14]
                o["verified"] = owner[13]
                owners.append(o)

            m = collections.OrderedDict()
            m["isMutable"] = rows[0][9]
            m["masterEdition"] = rows[0][10]
            m["metadatauri"] = rows[0][5]
            m["owners"] = owners
            m["primarySaleHappened"] = rows[0][8]
            m["sellerFeeBasisPoints"] = rows[0][7]
            m["updateauthority"] = rows[0][6]
            
            n = collections.OrderedDict()
            n["mint"] = rows[0][1]
            n["name"] = rows[0][2]
            n["standard"] = rows[0][3]
            n["symbol"] = rows[0][4]
            n['metaplex'] = m

            j = json.dumps(n)
            return render_template('result.html', table = json2html.convert(json = j))
        # If nft address is not in our table, try to get it through Moralis API
        else:
            response = requests.get(url.format(address), headers=headers).json()
            sleep(3)

            # In case of Bad Request
            if 'statusCode' in response:
                return '''<h1>NFT with this address not found</h1>'''

            # If the Bad Request did not occur, Moralis will return JSON with information about the NFT 
            # The code below saves this information to the DB
            with conn.cursor() as cur:
                cur.execute(""" CREATE TABLE IF NOT EXISTS owners(
                    owner_address text, nft_address text, verified integer, share integer, PRIMARY KEY (owner_address, nft_address)) """)
                query_sql = """ INSERT INTO owners(owner_address, nft_address, verified, share) VALUES(%s, %s, %s, %s) """
                for o in response['metaplex']['owners']:
                    cur.execute(query_sql, (o['address'], response['mint'], o['verified'], o['share'],))
                conn.commit()

                cur.execute(""" CREATE TABLE IF NOT EXISTS multiplex_table(
                    metaplex_id serial, metadataUri text, updateAuthority text, sellerFeeBasisPoints integer, primarySaleHappened integer, 
                    isMutable boolean, masterEdition boolean, PRIMARY KEY (metaplex_id)) """)
                query_sql = """ INSERT INTO multiplex_table(metadataUri, updateAuthority, sellerFeeBasisPoints, primarySaleHappened, 
                    isMutable, masterEdition) VALUES(%s, %s, %s, %s, %s, %s) """
                cur.execute(query_sql, (response['metaplex']['metadataUri'], response['metaplex']['updateAuthority'], 
                    response['metaplex']['sellerFeeBasisPoints'], response['metaplex']['primarySaleHappened'],
                    response['metaplex']['isMutable'], response['metaplex']['masterEdition'],))
                conn.commit() 

                cur.execute(""" CREATE TABLE IF NOT EXISTS nft_table(
                    mint text, name text, standard text, symbol text, metaplex_id serial, PRIMARY KEY (mint),
                    FOREIGN KEY (metaplex_id) REFERENCES multiplex_table(metaplex_id)) """)
                query_sql = """ INSERT INTO nft_table(mint, name, standard, symbol) VALUES(%s, %s, %s, %s) """ 
                cur.execute(query_sql, (response['mint'], response['name'], response['standard'], response['symbol'],))
                conn.commit()
            
            return render_template('result.html', table = json2html.convert(json = response))

    return render_template('search.html')  

@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        remember = form.remember.data

        user = Users.query.filter_by(name=username).first()
        if user:
            salt = bytes(user.password, 'utf-8')
            if bcrypt.checkpw(password.encode('utf-8'), salt):
                login_user(user, remember=remember)
                return redirect(url_for('search'))

    return render_template('login.html', form=form)

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data      

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        with conn.cursor() as cur:
            cur.execute(""" CREATE TABLE IF NOT EXISTS users(
                name text, email text, password text, PRIMARY KEY (name)) """)
            query_sql = """ INSERT INTO users(name, email, password) VALUES(%s, %s, %s) """
            cur.execute(query_sql, (username, email, hashed_password,))
            conn.commit()

        return redirect(url_for('login'))

    return render_template('signup.html', form=form)

@app.route("/logout", methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

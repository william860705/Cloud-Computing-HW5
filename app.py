import os
import flask
from flask import request, jsonify, redirect, url_for, flash
from flask_cors import CORS
from flask import render_template, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
# import database_helper as db_helper
app = flask.Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# app.config['MAIL_SERVER'] = 'smtp.gmail.com' 
app.config['MAIL_SERVER'] = 'smtp.live.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'bl605_test1111@hotmail.com'
app.config['MAIL_PASSWORD'] = 'Bl605_test'
mail = Mail(app)
db = SQLAlchemy(app)
CORS(app)

app.secret_key = "secretkey"

@app.route('/')
def home():
    if 'logged_in' in session:
        return redirect(url_for('welcome'))
    return redirect(url_for('login'))

@app.route('/welcome')
def welcome():
    islogin = False
    if 'logged_in' in session:
        islogin = True
    return render_template('welcome.html', islogin = islogin)

@app.route('/login', methods = ['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if ('email' in request.form and 'password' in request.form) and \
       (type(request.form['email'] == str) and type(request.form['password'] == str)):
            myctx = CryptContext(schemes=["sha256_crypt"])
            user = db.session.query(User).filter(User.email == request.form['email']).first()
            print(user)
            if user is None:
                error = 'email does not exist'
            elif not myctx.verify(request.form['password'], user.password):
                error = 'wrong email or password'
            else:
                session['logged_in'] = True
                session['current_user'] = user.username
                flash('hi! ' +  user.username)
                return redirect(url_for('welcome'))
    return render_template('login.html', error=error)

@app.route('/register', methods = ['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        print(request.form)
        if request.form['password'] != request.form['passwordConfirm']:
            error = 'password doest not match'
            print(error)
        elif len(request.form['password']) < 4:
            error = 'password must be longer than 4 characters'
            print(error)           
        else:
            user = {
                'username': request.form['username'],
                'password': request.form['password'],
                'email': request.form['email']
            }
            if create_user(user):
                return redirect(url_for('login'))
            else:
                error = 'email had been used by another account'
    return render_template('register.html', error=error)


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('current_user', None)
    # flash('logged out !')
    return redirect(url_for('login'))

@app.route('/forgot', methods = ['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        error = None
        user = db.session.query(User).filter(User.email == request.form['email']).first()
        if user is not None:
            send_reset_email(user)
            return redirect(url_for('login'))
        else:
            error = 'Email does not exist'
        return render_template('forgot.html', error = error)
    return render_template('forgot.html')

@app.route('/reset_password/<token>', methods = ['GET', 'POST'])
def reset_token(token):
    user = User.verify_reset_token(token)
    # print('User', user)
    error = None
    if request.method == 'POST': 
        if request.form['password'] != request.form['passwordConfirm']:
            error = 'password doest not match'
            print(error)
        elif len(request.form['password']) < 4:
            error = 'password must be longer than 4 characters'
            print(error)     
        else:
            req = {'password': request.form['password']}
            update_password(user, req)
            return redirect(url_for('login'))
        return render_template('reset_password.html', error = error) 
    return render_template('reset_password.html', error = error) 
    
# for debugging show all users
@app.route('/debug')
def show_table():
    users = User.query.all()
    message = []
    for user in users:
        user_data = {}
        user_data['id'] = user.id
        user_data['email'] = user.email
        user_data['username'] = user.username
        user_data['password'] = user.password
        message.append(user_data)
    return jsonify({'users':message})
'''
db_helper
'''

from sqlalchemy.sql import text
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta
key = 'secret'

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(60), nullable=False)
    password = db.Column(db.String(60), nullable=False)
    email = db.Column(db.Text(), nullable=False)
    status = db.Column(db.Boolean())

    datasets = db.relationship('Dataset', backref=db.backref('user', lazy=True))

    def get_reset_token(self, expires_sec =  1800):
        s = Serializer(app.secret_key, expires_sec)
        return s.dumps({'user_id':str(self.id)}).decode('utf-8')
    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.secret_key)
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

class Dataset(db.Model):
    __tablename__ = 'dataset'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text(), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey(User.id), nullable=False)
    file_path = db.Column(db.Text(), nullable=False)
    log_path = db.Column(db.Text())
    model_path = db.Column(db.Text())
    upload_date = db.Column(db.Text(), nullable=False)

def update_password(user, request):
    myctx = CryptContext(schemes=["sha256_crypt"])
    hashed_password = myctx.hash(request['password'])
    user.password = hashed_password
    db.session.commit()
    print('password reset')
    return True

def create_user(request):
    '''
    Create user in the database
    Password is encrypted with SHA256
    '''
    if ('username' in request and 'password' in request and 'email' in request) and \
       (type(request['username'] == str) and type(request['password'] == str) and type(request['email'] == str)):
        # duplicate = db.session.query(User).filter(User.username == request['username']).first()
        duplicate = db.session.query(User).filter(User.email == request['email']).first()
        if duplicate is None:
            myctx = CryptContext(schemes=["sha256_crypt"])
            new_user = User(
                username=request['username'],
                email=request['email'],
                password=myctx.hash(request['password'])
            )
            db.session.add(new_user)
            db.session.commit()
            return True
        else:
            print('register failed')
            return False
    else:
        return False

def create_dataset(path, name, token):
    id = token2id(token)
    if id is not None:
        new_dataset = Dataset(
            user_id=int(id),
            name = name,
            file_path=path,
            upload_date=datetime.today().strftime('%Y-%m-%d-%H:%M:%S')
        )
        db.session.add(new_dataset)
        db.session.commit()
        return True
    else:
        return False

def get_dataset(token):
    '''
    Datasets are returned as a list of 
    entries of dataset table matching ID in token
    '''
    id = token2id(token)
    if id is not None:
        user = db.session.query(User).filter(User.id == id).first()
        if user is not None:
            return user.datasets
        else:
            return None
    else:
        return None

def generate_token(username):
    '''
    Generate token with User ID
    the valid period of the token is 10 mins
    '''
    user = db.session.query(User).filter(User.username == username).first()
    if user is not None:
        payload = {
            'sub': str(user.id),
            'exp': datetime.utcnow() + timedelta(minutes=10),
            'nbf': datetime.utcnow(),
            'iat': datetime.utcnow(),
        }
        token = jwt.encode(payload, key, algorithm='HS256')
        return token
    else:
        return None

def create_token(username):
    '''
    Probably not needed, since we don't store token
    in the database
    '''
    user = db.session.query(User).filter(User.username == username).first()
    if user is not None:
        token = generate_token(user.id)
        user.token = token
        db.session.commit()
        return token
    else:
        return None

def token2id(token):
    '''
    Verify token
    Parameters:
        token: token in the payload
    
    Returns:
        User ID if token is valid, None vice versa
    '''
    try:
        payload = jwt.decode(token, key)
        if 'sub' in payload:
            return payload['sub']
        else:
            return None
    except Exception as e:
        print(e)
        return None

def login_(request):
    '''
    Verify the password in the request
    
    Parameters:
        request: request to login
    returns:
        True if password checks out, False vice versa
    '''
    if ('username' in request and 'password' in request) and \
       (type(request['username'] == str) and type(request['password'] == str)):
        myctx = CryptContext(schemes=["sha256_crypt"])
        user = db.session.query(User).filter(User.username == request['username']).first()
        if user is None:
            return False
        else:
            return myctx.verify(request['password'], user.password)
    else:
        return False
def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password reset', 
        sender=('no-reply', 'bl605_test1111@hotmail.com'), 
        recipients=[user.email])
    msg.body = f'''To reset your password, please visit :
{url_for('reset_token', token=token, _external=True)}
The token will expire in 10 minutes.
'''
    mail.send(msg)
    return True

# for debuging
def dataset2name(dataset):
    names = [d.name for d in dataset]
    return names


if __name__ == "__main__":
    app.run(debug=True)
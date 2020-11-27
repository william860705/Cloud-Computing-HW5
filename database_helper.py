from sqlalchemy.sql import text
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta

from app import db

# TODO: determine key for encryption
key = 'secret'

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(60), nullable=False)
    password = db.Column(db.String(60), nullable=False)
    email = db.Column(db.Text(), nullable=False)
    status = db.Column(db.Boolean())

    datasets = db.relationship('Dataset', backref=db.backref('user', lazy=True))

class Dataset(db.Model):
    __tablename__ = 'dataset'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text(), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey(User.id), nullable=False)
    file_path = db.Column(db.Text(), nullable=False)
    log_path = db.Column(db.Text())
    model_path = db.Column(db.Text())
    upload_date = db.Column(db.Text(), nullable=False)

def create_user(request):
    '''
    Create user in the database
    Password is encrypted with SHA256
    '''
    if ('username' in request and 'password' in request and 'email' in request) and \
       (type(request['username'] == str) and type(request['password'] == str) and type(request['email'] == str)):
        duplicate = db.session.query(User).filter(User.username == request['username']).first()
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

def login(request):
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

# db.create_all()

# for debuging
def dataset2name(dataset):
    names = [d.name for d in dataset]
    return names

db.drop_all()
db.create_all()
# user = {
#     'username': 'root',
#     'password': '1234',
#     'email': 'abc@def.com'
# }

user = {
    'username': 'admin',
    'password': 'admin',
    'email': 'admin@admin'
}
create_user(user)
u1 = db.session.query(User).filter(User.username == 'admin').first()
print(u1.email)
# token = generate_token(u1.username)
# u1 = db.session.query(User).filter(User.username == 'root').first()
# create_dataset('./test.csv', 'test', token)
# create_dataset('./test1.csv', 'test1', token)
# print(token)
# get_dataset(token)
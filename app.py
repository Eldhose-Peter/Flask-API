from flask import Flask,request,jsonify,make_response
from flask_mysqldb import MySQL
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from flask_cors import CORS, cross_origin

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisisecret'

app.config['MYSQL_USER'] = 'eldho2'
app.config['MYSQL_PASSWORD'] = 'Pass#2020'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_DB'] = 'librarymanagement'
app.config['MYSQL_CURSORCLASS']= 'DictCursor'

CORS(app)
mysql = MySQL(app)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            id = data['public_id']
            statement ="SELECT * FROM user WHERE userid = "+str(id)+" ;"
            cur = mysql.connection.cursor()
            cur.execute(statement)
            current_user = cur.fetchall()
            cur.close()
            #current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated



@app.route('/api/login' ,methods = ['POST','GET'])
def login():
    auth = request.get_json()
    print(auth)

    if not auth or not auth['username'] or not auth['password']:
        return make_response('Could not verify Auth', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    try:
    
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM user WHERE name = '" + auth['username']+"' ")
        user = cur.fetchall()
        cur.close()
    
    except:
        return make_response('Error in sql Query', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})


    if not user:
        response = make_response('user does not exist', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
        return response

    if check_password_hash(user[0]['password'], auth['password']):
        token = jwt.encode({'public_id' : user[0]['userid'], 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        response = jsonify({'token' : token.decode('UTF-8')})
        return response


    response = make_response('Could not verify password', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    return response

@app.route('/api/register',methods=['GET', 'POST'])
def register():

    data = request.get_json()

    username = data['username']
    hashed_password = generate_password_hash(data['password'],method='sha256')
    public_id = str(uuid.uuid4())

    try:
        cur = mysql.connection.cursor()
        statement = "INSERT INTO user (name,password) VALUES ('"+username+"','"+hashed_password+ "')"
        print(statement)
        cur.execute(statement)
        mysql.connection.commit()
        result= cur.fetchall()
        cur.close()

    except :
        return make_response('Could not create user', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    return jsonify({'message':'New user created !'})





@app.route('/api/home',methods = ['GET'])
def home():


    try:
    
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM Books")
        books = cur.fetchall()
        cur.close()
    
    except:
        return make_response('Error in sql Query', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})


    output=[]

    for book in books:
        book_data = {}
        book_data['id'] = book['book_id']
        book_data['title'] = book['title']
        book_data['count'] = book['count']
        output.append(book_data)

    return jsonify({'Books' : output})
    

@app.route('/api/borrow',methods = ['POST'])
@token_required
def borrow(current_user):

    data = request.get_json()

    user_id = current_user[0]['userid']
    book_id = data['book_id']
 

    try:
    
        cur = mysql.connection.cursor()
        cur.execute("UPDATE Books SET count = count-1 WHERE book_id ="+str(book_id))
        cur.execute("INSERT INTO library_card (user_id,book_id) values ("+str(user_id)+","+str(book_id)+")")
        mysql.connection.commit()
        result= cur.fetchall()
        cur.close()
    
    except:
        return make_response('Error in sql Query', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    return jsonify({'message':'Borrowed Book !'})

@app.route('/api/profile',methods = ['GET'])
@token_required
def profile(current_user):


    user_id = current_user[0]['userid']

    try:
    
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM user WHERE userid = "+str(user_id))
        user = cur.fetchall()
        cur.close()
    
    except:
        return make_response('Error in sql Query', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})


    output=[]

    for u in user:
        user_data = {}
        user_data['id'] = u['userid']
        user_data['name'] = u['name']
        user_data['age'] = u['age']
        output.append(user_data)

    return jsonify({'User' : output})



@app.route('/api/profile/history',methods = ['GET'])
@token_required
def history(current_user):

    user_id = current_user[0]['userid']

    try:
    
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM library_card INNER JOIN Books ON library_card.book_id = Books.book_id WHERE user_id = "+str(user_id))
        books = cur.fetchall()
        cur.close()
    
    except:
        return make_response('Error in sql Query', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})


    output=[]

    for book in books:
        book_data = {}
        book_data['id'] = book['book_id']
        book_data['title'] = book['title']
        book_data['author'] = book['author']
        book_data['genre'] = book['genre']
        book_data['issue_date'] = book['issue_date']
        book_data['has_returned'] = book['has_returned']

        output.append(book_data)

    return jsonify({'Books' : output})


@app.route('/api/profile/history/return',methods = ['POST'])
@token_required
def ret_urn(current_user):
    data = request.get_json()

    user_id = current_user[0]['userid']
    book_id = data['book_id']
 

    try:
    
        cur = mysql.connection.cursor()
        cur.execute("UPDATE Books SET count = count+1 WHERE book_id ="+str(book_id))
        cur.execute("UPDATE library_card SET has_returned = 1 WHERE book_id = "+str(book_id)+" AND user_id ="+str(user_id))
        mysql.connection.commit()
        result= cur.fetchall()
        cur.close()
    
    except:
        return make_response('Error in sql Query', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    return jsonify({'message':'Book returned !'})


#@app.route('/api/home/search',methods = ['GET'])
#@token_required
#def search(current_user):





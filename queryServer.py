from flask import Flask, request, redirect, url_for, jsonify
from flask_login import login_required, LoginManager, UserMixin, login_user, current_user
from werkzeug.security import check_password_hash
import sqlite3
from urllib.parse import urlparse, parse_qs
from blockchain import Blockchain, Block
import json
from datetime import datetime
import pytz

app = Flask(__name__)
app.secret_key = 'secret_key'
login_manager = LoginManager()
login_manager.init_app(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

blockchain = Blockchain()

class loginUser(UserMixin):
    audit_users = {
                    'alice': 'pbkdf2:sha256:260000$yMFmeJlSzF661LHr$3fd22051a19db631f4c46bea63d6c43f77c893201ccdb7b12900cb9c58b7c770',  #password1
                    'bob' : 'pbkdf2:sha256:260000$AQs5TJTsEBVXUk4o$c0067e62b4a9b0bdeec49aadd56e24136583adcbf3117af7eedfad49b641bd00',    #password2
                    'carl' : 'pbkdf2:sha256:260000$jevexjzerWaZmi6Z$16e87b52b7b6bd67629d569793f7cad334e318ef8f6b688f5ccf3ed561027de3'   #password3
                    }

    def __init__(self, username):
        self.username = username
        self.id = username
        # self.password = password

    def is_allowed(self):
        conn = sqlite3.connect('instance/sqlite.db')
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM user")
        rows = cursor.fetchall()
        users = [row[0] for row in rows]
        return self.username in loginUser.audit_users or self.username in users


@login_manager.user_loader
def load_user(user_id):
    return loginUser(user_id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    print(request.method)
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = loginUser(username)
        if not user.is_allowed():
            return
        if username in loginUser.audit_users:
            if not check_password_hash(loginUser.audit_users[username], password):
                return
        else:

            conn = sqlite3.connect('instance/sqlite.db')
            cursor = conn.cursor()
            cursor.execute(f"SELECT password_hash FROM user where name='{username}'")
            password_hash = cursor.fetchall()[0][0]

            if not check_password_hash(password_hash, password):
                return
        login_user(user)
        return "login success"
    parse = parse_qs(urlparse(request.args['next']).query)
    username = parse.get('username')[0]
    password = parse.get('password')[0]

    user = loginUser(username)
    if not user.is_allowed():
        return
    if username in loginUser.audit_users:
        if not check_password_hash(loginUser.audit_users[username], password):
            return
    else:

        conn = sqlite3.connect('instance/sqlite.db')
        cursor = conn.cursor()
        cursor.execute(f"SELECT password_hash FROM user where name='{username}'")
        password_hash = cursor.fetchall()[0][0]

        if not check_password_hash(password_hash, password):
            return
    login_user(user)
    path = urlparse(request.args['next']).path[1:]
    if path == 'query_database':
        return redirect(url_for(path, sql_code=parse.get('sql-code')[0]))
    elif path == 'post_blockchain':
        return redirect(url_for(path, blockchain={"blockchain" : json.loads(parse.get('blockchain')[0])}))
    elif path == 'add_block':
        return redirect(url_for(path, add_block={"block" : json.loads(parse.get('block')[0])}))
    return redirect(url_for(path, username=username))



@app.route('/query_database')
@login_required
def query_database():
    if request.method == 'GET':
        # sql_code = request.form['sql-code']
        sql_code = request.args.get('sql_code')

        # connect to the database
        conn = sqlite3.connect('./instance/sqlite.db')

        # create a cursor object
        cursor = conn.cursor()

        # execute the statement and fetch the results
        # cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        cursor.execute(sql_code)  # SELECT * FROM user;  SELECT * FROM audit_log;  DELETE FROM audit_log;
        results = cursor.fetchall()

        # close the cursor and connection
        cursor.close()
        conn.close()

        payload = {"results": results}   #SENSITIVE DATA
        return payload


@app.route('/get_usernames')
@login_required
def get_usernames():

    conn = sqlite3.connect('instance/sqlite.db')
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM user")
    rows = cursor.fetchall()
    users = [row[0] for row in rows]

    payload = {"users": users}

    return payload


@app.route('/get_hash')
@login_required
def get_hash():
    conn = sqlite3.connect('instance/sqlite.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT password_hash FROM user where name='{request.args.get('username')}'")
    password_hash = cursor.fetchall()[0][0]

    payload = {"password_hash": password_hash}

    return payload


@app.route('/add_block', methods=['GET', 'POST'])
@login_required
def add_block():
    data = json.loads(request.args['add_block'].replace("'", "\""))['block']
    blockchain.add_block(data)
    return 'Block added successfully'



@app.route('/post_blockchain', methods=['GET', 'POST'])
@login_required
def post_blockchain():
    blocks = json.loads(request.args['blockchain'].replace("'", "\""))
    blocks['blockchain'][0]['timestamp'] = datetime.fromisoformat(blocks['blockchain'][0]['timestamp'].replace('Z', '+00:00'))
    # blockchain.chain = blocks['blockchain']
    blockchain.chain[0] = Block(blocks['blockchain'][0]['index'], 
                                blocks['blockchain'][0]['timestamp'], 
                                blocks['blockchain'][0]['data'],
                                blocks['blockchain'][0]['previous_hash'])
    for block in blocks['blockchain'][1:]:
        block['data']['date_time'] = datetime.strptime(block['data']['date_time'], '%Y-%m-%dT%H:%M:%S.%f')
        blockchain.add_block(block['data'])
    return 'Block added successfully'



@app.route('/blockchain', methods=['GET'])
@login_required
def blockchain():
    return jsonify({"blockchain" : blockchain.to_dict()})

if __name__ == '__main__':
    with app.app_context():
        blockchain = Blockchain()
    app.run(port=5001)
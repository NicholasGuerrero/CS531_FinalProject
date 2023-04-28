from flask import Flask, render_template, redirect, url_for, request, session, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3
import datetime
import re
import pytz
import requests
import json
from buildmtree import MerkleTree
import threading
from genkeys import get_keys
from RSAcrypt import encrypt, decrypt
from blockchain import Blockchain, DateTimeEncoder


app = Flask(__name__)
app.secret_key = 'secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sqlite.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
blockchain = Blockchain()

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date_time = db.Column(db.DateTime, default=datetime.datetime.now(pytz.timezone('US/Pacific')))
    patient_id = db.Column(db.Integer)
    user_id = db.Column(db.String(50))
    action_type = db.Column(db.String(100))
        
    mTree = None

    def to_dict(self):
        return {
            "id": self.id,
            "date_time": self.date_time,
            "patient_id": self.patient_id,
            "user_id": self.user_id,
            "action_type": self.action_type
        }

def createBlockChain():
    #create BlockChain
    audit_logs = AuditLog.query.all()
    if len(audit_logs) != 0:
        for audit_record in audit_logs:
            blockchain.add_block(audit_record.to_dict())
    return

def createMerkelTree():
        # Create Merkel Tree
        audit_logs = AuditLog.query.all()
        if len(audit_logs) != 0:
            mTreeInput = [f"{audit_record.date_time}|{audit_record.patient_id}|{audit_record.user_id}|{audit_record.action_type}" for audit_record in AuditLog.query.all()]
            mTree = MerkleTree(mTreeInput)
            AuditLog.mTree = mTree
        return

def checkLogImmutability():
    audit_logs = AuditLog.query.all()
    if len(audit_logs) != 0:
        mTreeInput = [f"{audit_record.date_time}|{audit_record.patient_id}|{audit_record.user_id}|{audit_record.action_type}" for audit_record in AuditLog.query.all()]
        mTree = MerkleTree(mTreeInput)

        if mTree.root.hashHex != AuditLog.mTree.root.hashHex:
            return False
    return True

def manageAuditLog(log):
    # create a lock object
    lock = threading.Lock()
    # acquire the lock before executing the code
    lock.acquire()
    try:
        isImmutable = checkLogImmutability()

        if isImmutable == False:
            audit_record = AuditLog.query.get(1)
            audit_record.action_type = "query - SELECT * FROM audit_log;"
            db.session.commit()
            return False
        #  create audit log entry
        db.session.add(log)
        db.session.commit()

        #recreate Merkel Tree
        createMerkelTree()

        # add audit log entry as a block to the blockchain
        blockchain.add_block(log.to_dict())

         # Post blockchain block
        password = session.get('password')
        block = json.dumps(log.to_dict(), sort_keys=True, cls=DateTimeEncoder)
        response = requests.post('http://127.0.0.1:5001/add_block', data={'block' : block}, params={'username': current_user.id, 'password': password, 'block' : block})

    finally:
        # release the lock
        lock.release()
        if isImmutable == False:
            return False
        return True

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(50))
    dob = db.Column(db.String(50))
    gender = db.Column(db.String(50))
    blood_type = db.Column(db.String(50))
    medical_condition = db.Column(db.String(50))
    medication = db.Column(db.String(50))
    password_hash = db.Column(db.String(50))


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class loginUser(UserMixin):
    audit_users = {
                    'alice': 'pbkdf2:sha256:260000$yMFmeJlSzF661LHr$3fd22051a19db631f4c46bea63d6c43f77c893201ccdb7b12900cb9c58b7c770',  #password1
                    'bob' : 'pbkdf2:sha256:260000$AQs5TJTsEBVXUk4o$c0067e62b4a9b0bdeec49aadd56e24136583adcbf3117af7eedfad49b641bd00',    #password2
                    'carl' : 'pbkdf2:sha256:260000$jevexjzerWaZmi6Z$16e87b52b7b6bd67629d569793f7cad334e318ef8f6b688f5ccf3ed561027de3'   #password3
                    }

    def __init__(self, username):
        self.username = username
        self.id = username

    def is_allowed(self, data):
        response = requests.get('http://127.0.0.1:5001/get_usernames', params=data)
        payload = json.loads(response.text)
        users = payload['users']

        return self.username in loginUser.audit_users or self.username in users


@login_manager.user_loader
def load_user(user_id):
    return loginUser(user_id)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        session['password'] = password
        user = loginUser(username)
        # login to query server
        # response = requests.post('http://127.0.0.1:5001/login', data={'username': username, 'password': password})
        if not user.is_allowed(data={'username': username, 'password': password}):
            return render_template('unauthorized.html'), 401
        if username in loginUser.audit_users:
            if not check_password_hash(loginUser.audit_users[username], password):
                return render_template('unauthorized.html'), 401
        else:
            response = requests.get('http://127.0.0.1:5001/get_hash', params={'username': username, 'password': password})
            payload = json.loads(response.text)
            password_hash = payload['password_hash']

            if not check_password_hash(password_hash, password):
                return render_template('unauthorized.html'), 401
        login_user(user)

        # Post blockchain data
        password = session.get('password')
        json_blockchain = json.dumps(blockchain.to_dict()['chain'], sort_keys=True, cls=DateTimeEncoder)
        response = requests.post('http://127.0.0.1:5001/post_blockchain', data={'blockchain' : json_blockchain}, params={'username': current_user.id, 'password': password, 'blockchain' : json_blockchain})

        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.errorhandler(401)
def unauthorized(error):
    return render_template('401.html'), 401


# pass the function to the template context
@app.context_processor
def utility_processor():
    return dict(decrypt=decrypt)

@app.route('/')
@login_required
def index():
    if current_user.id == 'alice' or current_user.id == 'bob' or current_user.id == 'carl': # if superuser, show all users
        users = User.query.all()
    else: # show only the current user's data
        users = User.query.filter_by(name=current_user.id).all()
    return render_template('index2.html', users=users, audit_users=list(loginUser.audit_users.keys()) )


@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    name = request.form['name']
    get_keys(name)
    print(name)
    email = encrypt(request.form['email'], f'keys/{name}.pub')
    dob = encrypt(request.form['dob'], f'keys/{name}.pub')
    gender = encrypt(request.form['gender'], f'keys/{name}.pub')
    blood_type = encrypt(request.form['blood_type'], f'keys/{name}.pub')
    medical_condition = encrypt(request.form['medical_condition'], f'keys/{name}.pub')
    medication = encrypt(request.form['medication'], f'keys/{name}.pub')

    new_user = User(name=name, email=email, dob=dob, gender=gender, blood_type=blood_type,
                    medical_condition=medical_condition, medication=medication,
                    # password_hash = generate_password_hash('user)
                    )
    db.session.add(new_user)
    db.session.commit()
    new_user.password_hash = generate_password_hash('user' + str(new_user.id))

    log = AuditLog(patient_id=new_user.id, user_id=current_user.id, action_type='create')
    isSecure = manageAuditLog(log)
    if not isSecure:
        return "Warning: Audit Log Tampering Detected!!!"

    return redirect(url_for('index'))

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = User.query.get(user_id)
    if current_user.username not in loginUser.audit_users:
        return render_template('unauthorized.html'), 401
    if request.method == 'POST':
        user.name = request.form['name']
        user.email = encrypt(request.form['email'], "keys/" + user.name + ".pub")
        user.dob = encrypt(request.form['dob'], "keys/" + user.name + ".pub")
        user.gender = encrypt(request.form['gender'], "keys/" + user.name + ".pub")
        user.blood_type = encrypt(request.form['blood_type'], "keys/" + user.name + ".pub")
        user.medical_condition = encrypt(request.form['medical_condition'], "keys/" + user.name + ".pub")
        user.medication = encrypt(request.form['medication'], "keys/" + user.name + ".pub")
        db.session.commit()

        # create audit log entry
        log = AuditLog(patient_id=user.id, user_id=current_user.id, action_type='change')
        isSecure = manageAuditLog(log)
        if not isSecure:
            return "Warning: Audit Log Tampering Detected!!!"

        return redirect(url_for('index'))
    return render_template('edit_user.html', user=user)


@app.route('/delete_user/<int:user_id>', methods=['GET', 'POST'])
def delete_user(user_id):
    if current_user.username not in loginUser.audit_users:
        return render_template('unauthorized.html'), 401

    user = User.query.get(user_id)
    db.session.delete(user)
    db.session.commit()

    # create audit log entry
    log = AuditLog(patient_id=user_id, user_id=current_user.id, action_type='delete')
    isSecure = manageAuditLog(log)
    if not isSecure:
        return "Warning: Audit Log Tampering Detected!!!"

    return redirect(url_for('index'))


@app.route('/query_database', methods=['GET', 'POST'])
@login_required
def query_database():
    if request.method == 'POST':

        sql_code = request.form['sql-code']

        # Extract the table name from the SQL code
        match = re.search(r"FROM\s+([^\s;]+)", sql_code, re.IGNORECASE)
        if match:
            table_name = match.group(1)
        else:
            table_name = None

        # Patients can query the system to monitor usage of only their own EHR data.
        if table_name == 'audit_log':
            if current_user.id not in loginUser.audit_users:
                id_num = User.query.filter_by(name=current_user.id).all()[0].id
                sql_code = sql_code[:-1] + ' WHERE patient_id=' + str(id_num) 
        elif table_name == 'user':
            if current_user.id not in loginUser.audit_users:
                id_num = User.query.filter_by(name=current_user.id).all()[0].id
                sql_code = sql_code[:-1] + ' WHERE id=' + str(id_num) 


        # Check for potentially harmful statements
        if re.search(r"(DROP|TRUNCATE)\s+TABLE", sql_code, re.IGNORECASE):
            return "Table deletion is not allowed"
        elif re.search(r"DELETE\s+FROM", sql_code, re.IGNORECASE):
            return "Record deletion is not allowed"
        elif re.search(r"INSERT\s+INTO", sql_code, re.IGNORECASE):
            return "Record insertion is not allowed"
        elif re.search(r"CREATE\s+TABLE", sql_code, re.IGNORECASE):
            return "Table creation is not allowed"

        # Make a request to the Query Server
        password = session.get('password')
        response = requests.get('http://127.0.0.1:5001/query_database', data={'sql-code': sql_code}, params={'username': current_user.id, 'password': password, 'sql-code': sql_code})
        payload = json.loads(response.text)
        results = payload['results']


        if table_name == 'audit_log':
            if current_user.id in loginUser.audit_users:
                patient_ids = current_user.id
            else:
                patient_ids = User.query.filter_by(name=current_user.id).all()[0].id
        elif table_name == 'user':
            for tup in results:
                patient_ids = tup[0]
            
            #decrypt records
            for i in range(len(results)):
                for j in range(2, 8):
                    results[i][j] = decrypt(results[i][j], "keys/" + results[i][1] + ".prv")

        log = AuditLog(patient_id=str(patient_ids), user_id=current_user.id, action_type='query - ' + sql_code)
        isSecure = manageAuditLog(log)
        if not isSecure:
            return "Warning: Audit Log Tampering Detected!!!"

        return render_template('query_result.html', results=results, table_name=table_name)
    return render_template('query_database.html')


@app.route('/tamper', methods=['POST'])
def tamper_audit_log():
    if request.form.get('tamper'):
        audit_record = AuditLog.query.get(1)
        audit_record.action_type = "Tamperered With"
        db.session.commit()
        return redirect(url_for('index'))


@app.route('/blockchain', methods=['GET'])
@login_required
def get_blockchain():
    return jsonify({"blockchain" : blockchain.to_dict()})


@app.route('/MerkelTree', methods=['GET'])
@login_required
def get_MerkelTree():
    return AuditLog.mTree.jsonTree

@app.route('/EncryptedUsers', methods=['GET'])
@login_required
def get_EncryptedUsers():
    sql_code = "SELECT * FROM user;"
    password = session.get('password')
    response = requests.get('http://127.0.0.1:5001/query_database', data={'sql-code': sql_code}, params={'username': current_user.id, 'password': password, 'sql-code': sql_code})
    return json.loads(response.text)['results']

if __name__ == '__main__':
    with app.app_context():
        createMerkelTree()
        createBlockChain()
    app.run(port=5000)
    

from flask import Flask, render_template, redirect, url_for, request, session
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


app = Flask(__name__)
app.secret_key = 'secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sqlite.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date_time = db.Column(db.DateTime, default=datetime.datetime.now(pytz.timezone('US/Pacific')))
    patient_id = db.Column(db.Integer)
    user_id = db.Column(db.String(50))
    action_type = db.Column(db.String(100))
        
    mTree = None

def createMerkelTree():
        # Create Merkel Tree
        audit_logs = AuditLog.query.all()
        if len(audit_logs) != 0:
            mTreeInput = [f"{audit_record.date_time}|{audit_record.patient_id}|{audit_record.user_id}|{audit_record.action_type}" for audit_record in AuditLog.query.all()]
            mTree = MerkleTree(mTreeInput)
            AuditLog.mTree = mTree

def checkLogImmutability():
    audit_logs = AuditLog.query.all()
    if len(audit_logs) != 0:
        mTreeInput = [f"{audit_record.date_time}|{audit_record.patient_id}|{audit_record.user_id}|{audit_record.action_type}" for audit_record in AuditLog.query.all()]
        mTree = MerkleTree(mTreeInput)

        if mTree.root.hashHex != AuditLog.mTree.root.hashHex:
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
        # conn = sqlite3.connect('instance/sqlite.db')
        # cursor = conn.cursor()
        # cursor.execute("SELECT name FROM user")
        # rows = cursor.fetchall()
        # users = [row[0] for row in rows]

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
        
        response = requests.post('http://127.0.0.1:5001/login', data={'username': username, 'password': password})
        

        if not user.is_allowed(data={'username': username, 'password': password}):
            return render_template('unauthorized.html'), 401
        if username in loginUser.audit_users:
            if not check_password_hash(loginUser.audit_users[username], password):
                return render_template('unauthorized.html'), 401
        else:

            # conn = sqlite3.connect('instance/sqlite.db')
            # cursor = conn.cursor()
            # cursor.execute(f"SELECT password_hash FROM user where name='{username}'")
            # password_hash = cursor.fetchall()[0][0]

            response = requests.get('http://127.0.0.1:5001/get_hash', params={'username': username, 'password': password})
            payload = json.loads(response.text)
            password_hash = payload['password_hash']


            if not check_password_hash(password_hash, password):
                return render_template('unauthorized.html'), 401
        login_user(user)
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


@app.route('/')
@login_required
def index():
    if current_user.id == 'alice' or current_user.id == 'bob' or current_user.id == 'carl': # if superuser, show all users
        users = User.query.all()
        createMerkelTree()
    else: # show only the current user's data
        users = User.query.filter_by(name=current_user.id).all()
        createMerkelTree()
    return render_template('index2.html', users=users, audit_users=list(loginUser.audit_users.keys()) )


@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    name = request.form['name']
    email = request.form['email']
    dob = request.form['dob']
    gender = request.form['gender']
    blood_type = request.form['blood_type']
    medical_condition = request.form['medical_condition']
    medication = request.form['medication']
    new_user = User(name=name, email=email, dob=dob, gender=gender, blood_type=blood_type,
                    medical_condition=medical_condition, medication=medication,
                    # password_hash = generate_password_hash('user)
                    )
    db.session.add(new_user)
    db.session.commit()
    new_user.password_hash = generate_password_hash('user' + str(new_user.id))


    checkLogImmutability()

    # create audit log entry
    log = AuditLog(patient_id=new_user.id, user_id=current_user.id, action_type='create')
    db.session.add(log)
    db.session.commit()

    createMerkelTree()

    return redirect(url_for('index'))

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = User.query.get(user_id)
    if current_user.username not in loginUser.audit_users:
        return render_template('unauthorized.html'), 401
    if request.method == 'POST':
        user.name = request.form['name']
        user.email = request.form['email']
        user.dob = request.form['dob']
        user.gender = request.form['gender']
        user.blood_type = request.form['blood_type']
        user.medical_condition = request.form['medical_condition']
        user.medication = request.form['medication']
        db.session.commit()


        checkLogImmutability()

        # create audit log entry
        log = AuditLog(patient_id=user.id, user_id=current_user.id, action_type='change')
        db.session.add(log)
        db.session.commit()

        createMerkelTree()

        return redirect(url_for('index'))
    return render_template('edit_user.html', user=user)


@app.route('/delete_user/<int:user_id>', methods=['GET', 'POST'])
def delete_user(user_id):
    if current_user.username not in loginUser.audit_users:
        return render_template('unauthorized.html'), 401

    user = User.query.get(user_id)
    db.session.delete(user)
    db.session.commit()


    checkLogImmutability()
    # create audit log entry
    log = AuditLog(patient_id=user_id, user_id=current_user.id, action_type='delete')
    db.session.add(log)
    db.session.commit()
    createMerkelTree()

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

        # audit_record = AuditLog.query.get(1)
        # audit_record.action_type = "Tamperered With"
        # # audit_record.action_type = "query - SELECT * FROM audit_log;"
        # db.session.commit()


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
                return "Warning: Audit Log Tampering Detected!!!"
            #  create audit log entry
            log = AuditLog(patient_id=str(patient_ids), user_id=current_user.id, action_type='query - ' + sql_code)
            db.session.add(log)
            db.session.commit()

            createMerkelTree()
        finally:
            # release the lock
            lock.release()

        return render_template('query_result.html', results=results, table_name=table_name)
    return render_template('query_database.html')


@app.route('/tamper', methods=['POST'])
def tamper_audit_log():
    if request.form.get('tamper'):
        audit_record = AuditLog.query.get(1)
        audit_record.action_type = "Tamperered With"
        db.session.commit()
        return redirect(url_for('query_database'))

if __name__ == '__main__':
    app.run(port=5000)
    










# @app.route('/query_database', methods=['GET', 'POST'])
# @login_required
# def query_database():
#     if request.method == 'POST':
#         sql_code = request.form['sql-code']

#         # Extract the table name from the SQL code
#         match = re.search(r"FROM\s+([^\s;]+)", sql_code, re.IGNORECASE)
#         if match:
#             table_name = match.group(1)
#         else:
#             table_name = None

#         # Patients can query the system to monitor usage of only their own EHR data.
#         if table_name == 'audit_log':
#             if current_user.id not in loginUser.audit_users:
#                 id_num = User.query.filter_by(name=current_user.id).all()[0].id
#                 sql_code = sql_code[:-1] + ' WHERE patient_id=' + str(id_num) 
#         elif table_name == 'user':
#             if current_user.id not in loginUser.audit_users:
#                 id_num = User.query.filter_by(name=current_user.id).all()[0].id
#                 sql_code = sql_code[:-1] + ' WHERE id=' + str(id_num) 

#         # Check for potentially harmful statements
#         if re.search(r"(DROP|TRUNCATE)\s+TABLE", sql_code, re.IGNORECASE):
#             return "Table deletion is not allowed"
#         elif re.search(r"DELETE\s+FROM", sql_code, re.IGNORECASE):
#             return "Record deletion is not allowed"
#         elif re.search(r"INSERT\s+INTO", sql_code, re.IGNORECASE):
#             return "Record insertion is not allowed"
#         elif re.search(r"CREATE\s+TABLE", sql_code, re.IGNORECASE):
#             return "Table creation is not allowed"

#         # connect to the database
#         conn = sqlite3.connect('./instance/sqlite.db')

#         # create a cursor object
#         cursor = conn.cursor()

#         # execute the statement and fetch the results
#         # cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
#         cursor.execute(sql_code)  # SELECT * FROM user;  SELECT * FROM audit_log;  DELETE FROM audit_log;
#         results = cursor.fetchall()

#         # close the cursor and connection
#         cursor.close()
#         conn.close()

#         if table_name == 'audit_log':
#             if current_user.id in loginUser.audit_users:
#                 patient_ids = current_user.id
#             else:
#                 patient_ids = User.query.filter_by(name=current_user.id).all()[0].id
#         elif table_name == 'user':
#             # Patient ids returned in Query
#             # patient_ids = []
#             for tup in results:
#                 patient_ids = tup[0]
#             #     patient_ids.append(tup[0]) 

#          # create audit log entry
#         log = AuditLog(patient_id=str(patient_ids), user_id=current_user.id, action_type='query - ' + sql_code)
#         db.session.add(log)
#         db.session.commit()

#         return render_template('query_result.html', results=results, table_name=table_name)
#     return render_template('query_database.html')



# if len(AuditLog.mTree.leaves) >= 3:
        #     # Check Consistency of Merkel Tree to support Immutability Requirement
        #     mTreeInput = [f"{audit_record.date_time}|{audit_record.patient_id}|{audit_record.user_id}|{audit_record.action_type}" for audit_record in AuditLog.query.all()]
        #     bigTree = MerkleTree(mTreeInput)
        #     subTree = AuditLog.mTree


        #     isConsistent, proof = checkConsistency(subTree, bigTree)
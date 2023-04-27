from flask import Flask, request, jsonify
from hfc.fabric import Client
import hashlib
import time

app = Flask(__name__)
cli = Client(net_profile="connection.yaml")

# Define the route for submitting a new log entry to Hyperledger
@app.route('/api/submit', methods=['POST'])
def submit_log_entry():
    try:
        # Parse the JSON data from the request
        data = request.get_json()
        # Extract the log data from the data
        log_data = data['log_data']
        # Calculate the hash of the log data
        hash_value = hashlib.sha256(log_data.encode('utf-8')).hexdigest()
        # Get a handle to the chaincode function for submitting transactions
        cc = cli.get_chaincode('my_chaincode')
        # Invoke the chaincode function to submit the log entry
        response = cc.invoke('submit_log_entry', log_data, hash_value)
        # Return a JSON response with the result of the transaction
        return jsonify({'status': 'success', 'response': response})
    except Exception as e:
        # If there is an error, return a JSON response with the error message
        return jsonify({'status': 'error', 'message': str(e)})

# Define the route for getting the latest log entry hash value
@app.route('/api/latest', methods=['GET'])
def get_latest_log_entry():
    try:
        # Get a handle to the chaincode function for querying the ledger
        cc = cli.get_chaincode('my_chaincode')
        # Invoke the chaincode function to get the latest log entry hash value
        hash_value = cc.query('get_latest_log_entry')
        # Return a JSON response with the latest log entry hash value
        return jsonify({'status': 'success', 'hash_value': hash_value})
    except Exception as e:
        # If there is an error, return a JSON response with the error message
        return jsonify({'status': 'error', 'message': str(e)})

# Define a background task to monitor the log file for changes
def monitor_log_file():
    last_hash = None
    while True:
        # Get the latest log entry hash value
        hash_value = get_latest_log_entry()['hash_value']
        # If the hash value has changed since the last time we checked, report the change
        if hash_value != last_hash:
            print(f"Log file has changed! New hash value: {hash_value}")
            last_hash = hash_value
        # Sleep for 1 second before checking again
        time.sleep(1)

if __name__ == '__main__':
    # Start the background task to monitor the log file
    import threading
    threading.Thread(target=monitor_log_file, daemon=True).start()

    # Start the Flask app
    app.run(debug=True)


    # app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
# db = SQLAlchemy(app)

# class Patient(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     first_name = db.Column(db.String(50))
#     last_name = db.Column(db.String(50))
#     dob = db.Column(db.Date)
#     gender = db.Column(db.String(10))
#     address = db.Column(db.String(200))
#     phone_number = db.Column(db.String(20))
#     email = db.Column(db.String(100))

# # create database table
# db.create_all()

# # add 10 rows of dummy data
# patients = [
#     Patient(first_name='John', last_name='Doe', dob='1970-01-01', gender='Male',
#             address='123 Main St, Anytown, USA', phone_number='555-1234', email='johndoe@email.com'),
#     Patient(first_name='Jane', last_name='Doe', dob='1975-05-15', gender='Female',
#             address='456 Elm St, Anytown, USA', phone_number='555-5678', email='janedoe@email.com'),
#     Patient(first_name='Alice', last_name='Smith', dob='1980-07-10', gender='Female',
#             address='789 Oak St, Anytown, USA', phone_number='555-9012', email='alice@email.com'),
#     Patient(first_name='Bob', last_name='Jones', dob='1990-03-25', gender='Male',
#             address='321 Cedar St, Anytown, USA', phone_number='555-3456', email='bob@email.com'),
#     Patient(first_name='Maggie', last_name='Lee', dob='1985-12-01', gender='Female',
#             address='987 Pine St, Anytown, USA', phone_number='555-7890', email='maggie@email.com'),
#     Patient(first_name='David', last_name='Johnson', dob='1978-04-30', gender='Male',
#             address='654 Birch St, Anytown, USA', phone_number='555-2345', email='david@email.com'),
#     Patient(first_name='Samantha', last_name='Brown', dob='1992-09-20', gender='Female',
#             address='432 Maple St, Anytown, USA', phone_number='555-6789', email='samantha@email.com'),
#     Patient(first_name='Kevin', last_name='Wong', dob='1987-06-05', gender='Male',
#             address='876 Walnut St, Anytown, USA', phone_number='555-0123', email='kevin@email.com'),
#     Patient(first_name='Lauren', last_name='Kim', dob='1995-11-18', gender='Female',
#             address='135 Cedar St, Anytown, USA', phone_number='555-4567', email='lauren@email.com'),
#     Patient(first_name='Jacob', last_name='Nguyen', dob='1998-02-12', gender='Male',
#             address='246 Oak St, Anytown, USA', phone_number='555-8901', email='jacob@email.com')
# ]

# # add patients to the database
# db.session.add_all(patients)
# db.session.commit()


# from flask import Flask, render_template, redirect, url_for, request
# from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin
# from flask_sqlalchemy import SQLAlchemy

# app = Flask(__name__)
# app.secret_key = 'secret_key'

# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# db = SQLAlchemy(app)

# login_manager = LoginManager()
# login_manager.init_app(app)
# login_manager.login_view = 'login'

# class User(UserMixin, db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(64), unique=True, nullable=False)
#     password = db.Column(db.String(128), nullable=False)

#     allowed_users = ['alice', 'bob']

#     def __init__(self, username, password):
#         self.username = username
#         self.password = password

#     def is_allowed(self):
#         return self.username in User.allowed_users

# @login_manager.user_loader
# def load_user(user_id):
#     return User.query.filter_by(id=user_id).first()

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         user = User.query.filter_by(username=username, password=password).first()
#         if user is None or not user.is_allowed():
#             return render_template('unauthorized.html'), 401
#         login_user(user)
#         return redirect(url_for('index'))
#     return render_template('login.html')

# @app.route('/logout')
# @login_required
# def logout():
#     logout_user()
#     return redirect(url_for('login'))

# @app.route('/')
# @login_required
# def index():
#     return render_template('index.html')

# @app.errorhandler(401)
# def unauthorized(error):
#     return render_template('401.html'), 401

# with app.app_context():
#     db.create_all()

#     # add some dummy data
#     alice = User('alice', 'password')
#     bob = User('bob', 'password')
#     db.session.add(alice)
#     db.session.add(bob)
#     db.session.commit()

# if __name__ == '__main__':
#     app.run()



# //////////
# from flask import Flask, render_template, request, redirect, url_for
# from flask_sqlalchemy import SQLAlchemy
# from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin


# app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sqlite.db'
# db = SQLAlchemy(app)

# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(50))
#     email = db.Column(db.String(50))


# @app.route('/add_user', methods=['POST'])
# def add_user():
#     name = request.form['name']
#     email = request.form['email']
#     new_user = User(name=name, email=email)
#     db.session.add(new_user)
#     db.session.commit()
#     return redirect(url_for('index'))


# @app.route('/')
# def index():
#     users = User.query.all()
#     return render_template('index2.html', users=users)


# @app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
# def edit_user(user_id):
#     user = User.query.get(user_id)
#     if request.method == 'POST':
#         user.name = request.form['name']
#         user.email = request.form['email']
#         db.session.commit()
#         return redirect(url_for('index'))
#     return render_template('edit_user.html', user=user)


# @app.route('/delete_user/<int:user_id>', methods=['GET', 'POST'])
# def delete_user(user_id):
#     user = User.query.get(user_id)
#     db.session.delete(user)
#     db.session.commit()
#     return redirect(url_for('index'))

# if __name__ == '__main__':
#     app.run()

#//////





# To add an audit log every time the database is edited in some way, you can create a new table in the database to store the audit log entries. Here's an example of how you could modify the existing Flask app to implement this:

# Create a new model for the audit log:
# python
# Copy code
# class AuditLog(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
#     action = db.Column(db.String(50))
#     timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
# This model has columns for the ID of the user who performed the action, the action that was performed (e.g. "added user", "edited user", "deleted user"), and the timestamp of when the action was performed. The user_id column is a foreign key that references the ID column of the User model.

# Modify the existing add_user, edit_user, and delete_user routes to add audit log entries:
# python
# Copy code
# @app.route('/add_user', methods=['POST'])
# def add_user():
#     name = request.form['name']
#     email = request.form['email']
#     new_user = User(name=name, email=email)
#     db.session.add(new_user)
#     db.session.commit()

#     # add audit log entry
#     log_entry = AuditLog(user_id=current_user.id, action='added user')
#     db.session.add(log_entry)
#     db.session.commit()

#     return redirect(url_for('index'))

# @app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
# def edit_user(user_id):
#     user = User.query.get(user_id)
#     if request.method == 'POST':
#         user.name = request.form['name']
#         user.email = request.form['email']
#         db.session.commit()

#         # add audit log entry
#         log_entry = AuditLog(user_id=current_user.id, action='edited user')
#         db.session.add(log_entry)
#         db.session.commit()

#         return redirect(url_for('index'))
#     return render_template('edit_user.html', user=user)

# @app.route('/delete_user/<int:user_id>', methods=['GET', 'POST'])
# def delete_user(user_id):
#     user = User.query.get(user_id)
#     db.session.delete(user)
#     db.session.commit()

#     # add audit log entry
#     log_entry = AuditLog(user_id=current_user.id, action='deleted user')
#     db.session.add(log_entry)
#     db.session.commit()

#     return redirect(url_for('index'))
# These routes now create an AuditLog object after performing the database action, with the user_id set to the ID of the current user (obtained via current_user.id) and the action set to the appropriate string.

# Note that you will need to import datetime and current_user from the appropriate modules:

# python
# Copy code
# import datetime
# from flask_login import current_user
# With these modifications, every time a user adds, edits, or deletes a user, an audit log entry will be created in the AuditLog table with the user's ID, the action taken, and the current timestamp.



"""
The check_password_hash and generate_password_hash functions from the werkzeug.security module are secure.

generate_password_hash uses a one-way hashing algorithm, which means that once the password is hashed, it cannot be reversed to reveal the original password. This is important because if someone gains access to the hash of a user's password, they cannot simply reverse the hash to obtain the password.

Additionally, generate_password_hash uses a strong and adaptive hash function called pbkdf2:sha256 by default, which makes it difficult for an attacker to use a brute-force or dictionary attack to guess the password.

check_password_hash is also secure because it compares the provided password to the hash of the actual password using a constant-time comparison algorithm. This helps prevent timing attacks, where an attacker could use the response time of the comparison to guess the password one character at a time.

Overall, using these functions from werkzeug.security is a good practice for securing password storage in a Flask application.
"""
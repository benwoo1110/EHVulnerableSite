import os
from flask import Flask, render_template, redirect, request, make_response, abort, flash, url_for, send_from_directory
import jwt
import hashlib
import json
from werkzeug.utils import secure_filename


SECRET = 'secret'
USERSDB = {}
UPLOAD_FOLDER = 'templates/uploads'
ALLOWED_EXTENSIONS = {'html', 'xml'}


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


with open("usersdb.json", "r") as f:
    USERSDB = json.load(f)


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.md5(request.form['password'].encode("utf-8")).hexdigest()
        
        if username in USERSDB and USERSDB[username]["password"] == password:
            payload = {'username': USERSDB[username]["password"], 'type': USERSDB[username]["type"]}
            token = jwt.encode(payload, SECRET, algorithm='HS256')
            response = make_response(redirect('/home'))
            response.set_cookie('token', token, httponly=True)
            return response
        else:
            abort(401)

    elif request.method == 'GET':
        token = request.cookies.get('token')
        if token:
            try:
                jwt.decode(token, SECRET, algorithms=['HS256'])
                return redirect('/home')
            except jwt.InvalidTokenError:
                pass
        return render_template('login.html')


@app.route('/logout', methods=['POST'])
def logout():
    response = make_response(redirect('/login'))
    response.set_cookie('token', '', expires=0)
    return response


@app.route('/home')
def home():
    token = request.cookies.get('token')
    if token:
        try:
            jwt.decode(token, SECRET, algorithms=['HS256'])
            return render_template('home.html')
        except jwt.InvalidTokenError:
            pass
    return redirect('/login')


@app.route('/admin')
def admin():
    token = request.cookies.get('token')
    if token:
        try:
            payload = jwt.decode(token, SECRET, algorithms=['HS256'])
            if payload['type'] == 'admin':
                return render_template('admin.html')
            else:
                abort(403)
        except jwt.InvalidTokenError:
            pass
    return redirect('/login')


@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        #flash('No file part')
        abort(400)

    file = request.files['file']
    if file.filename == '':
        #flash('No selected file')
        abort(400)
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return redirect(url_for('download_file', name=filename))

    abort(400)


@app.route('/pages/<name>')
def download_file(name):
    return render_template(f"uploads/{secure_filename(name)}")


@app.route('/public')
def public():
    return #TODO


if __name__ == '__main__':
    app.run(debug=True)

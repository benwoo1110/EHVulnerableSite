import os
import glob
from flask import Flask, render_template, redirect, request, make_response, abort, flash, url_for, send_from_directory
import jwt
import hashlib
import json
from werkzeug.utils import secure_filename


UPLOAD_FOLDER = 'templates/uploads'
ALLOWED_EXTENSIONS = {'html'}
USERSDB = 'usersdb.json'
PUBLIC_KEY = 'public.key'
PRIVATE_KEY = 'private.key'


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def auth(token, admin: bool = False):
    payload = jwt.decode(token, PUBLIC_KEY, algorithms=['RS256', 'HS256'])
    if payload['username'] not in USERSDB:
        return None
    if admin and payload['type'] != 'admin':
        return None
    return payload


with open("usersdb.json", "r") as f:
    USERSDB = json.load(f)


with open(PUBLIC_KEY, 'r') as f:
    PUBLIC_KEY = f.read()


with open(PRIVATE_KEY, 'r') as f:
    PRIVATE_KEY = f.read()


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route('/')
def index():
    token = request.cookies.get('token')
    try:
        payload = auth(token)
        if payload != None:
            return redirect(url_for('home'))
    except jwt.InvalidTokenError:
        pass
    
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.md5(request.form['password'].encode("utf-8")).hexdigest()
        
        if username in USERSDB and USERSDB[username]["password"] == password:
            payload = {'username': USERSDB[username]["username"], 'type': USERSDB[username]["type"]}
            token = jwt.encode(payload, PRIVATE_KEY, algorithm='RS256')
            response = make_response(redirect('/home'))
            response.set_cookie('token', token, httponly=True)
            return response
        else:
            abort(401)

    elif request.method == 'GET':
        token = request.cookies.get('token')
        if token:
            try:
                jwt.decode(token, PUBLIC_KEY, algorithms=['RS256', 'HS256'])
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
            payload = auth(token)
            if payload != None:
                return render_template('home.html', admin=payload['type'] == 'admin')
        except jwt.InvalidTokenError:
            pass
    return redirect('/login')


@app.route('/admin')
def admin():
    token = request.cookies.get('token')
    if token:
        try:
            payload = auth(token, admin=True)
            if payload != None:
                files = glob.glob(UPLOAD_FOLDER + '/*')
                files = [os.path.basename(file) for file in files]
                return render_template('admin.html', files=files)
            else:
                abort(403)
        except jwt.InvalidTokenError:
            pass
    return redirect('/login')


@app.route('/file/upload', methods=['POST'])
def upload():
    token = request.cookies.get('token')
    if not token:
        abort(401)
    
    try:
        payload = auth(token, admin=True)
        if payload == None:
            abort(403)
    except jwt.InvalidTokenError:
        abort(403)

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


@app.route('/file/delete', methods=['POST'])
def delete():
    token = request.cookies.get('token')
    if not token:
        abort(401)
    
    try:
        payload = auth(token, admin=True)
        if payload == None:
            abort(403)
    except jwt.InvalidTokenError:
        abort(403)

    filename = request.form['file']
    filename = secure_filename(filename)
    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return redirect(url_for('admin'))


@app.route('/pages/<name>')
def download_file(name):
    return render_template(f"uploads/{secure_filename(name)}")


@app.route('/public')
def public():
    return PUBLIC_KEY


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)

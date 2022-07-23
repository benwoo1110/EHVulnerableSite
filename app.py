from flask import Flask, render_template, redirect, request, make_response, abort
import jwt


app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'admin' and password == 'admin':
            token = jwt.encode({'username': username}, 'secret', algorithm='HS256')
            response = make_response(redirect('/'))
            response.set_cookie('token', token, httponly=True)
            return response
        else:
            abort(401)

    elif request.method == 'GET':
        token = request.cookies.get('token')
        if token:
            try:
                jwt.decode(token, 'secret', algorithms=['HS256'])
                return render_template('home.html')
            except jwt.InvalidTokenError:
                pass
        return render_template('login.html')


@app.route('/logout', methods=['POST'])
def logout():
    response = make_response(redirect('/'))
    response.set_cookie('token', '', expires=0)
    return response


@app.route('/home')
def home():
    token = request.cookies.get('token')
    if token:
        try:
            jwt.decode(token, 'secret', algorithms=['HS256'])
            return render_template('home.html')
        except jwt.InvalidTokenError:
            pass
    return redirect('/login')



@app.route('/admin')
def admin():
    token = request.cookies.get('token')
    if token:
        try:
            jwt.decode(token, 'secret', algorithms=['HS256'])
            return render_template('admin.html')
        except jwt.InvalidTokenError:
            pass
    return redirect('/login')


@app.route('/public')
def public():
    return #TODO


if __name__ == '__main__':
    app.run(debug=True)

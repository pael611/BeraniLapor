from pymongo import MongoClient
import jwt
import datetime
import hashlib
from flask import Flask, render_template, jsonify, request, redirect, url_for, make_response, flash,session
from werkzeug.utils import secure_filename
import os
from os.path import join, dirname
from datetime import datetime, timedelta
from bson import ObjectId
from dotenv import load_dotenv
dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)

MONGODB_URI = os.environ.get("MONGODB_URI")
DB_NAME =  os.environ.get("DB_NAME")

client = MongoClient(MONGODB_URI)

db = client[DB_NAME]

SECRET_KEY = os.environ.get("SECRET_KEY")

app=Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
# Index / Landing Page!
@app.route('/',methods=['GET','POST'])
def home():
    if request.method=='POST':
        # Handle POST Request here
        return render_template('index.html')
    return render_template('index.html')


# User Function Here!!!
@app.route('/loginUser', methods=['GET', 'POST'])
def loginUser():
    if request.method == 'POST':
        # Handle POST Request here
        return render_template('login.html')
    return render_template('login.html')

@app.route('/sign_in', methods=['POST'])
def sign_in():
    username_receive = request.form.get('username_give')
    password_receive = request.form.get('password_give')
    # pw_hash = hashlib.sha256(password_receive.encode('utf-8')).hexdigest()
    
    # result = db.users.find_one({
    #     'username': username_receive,
    #     'password': pw_hash,
    # })
    
    # if result:
    #     payload = {
    #         'id': username_receive,
    #         # Token bisa berlaku sampai 24 jam
    #         'exp': datetime.utcnow() + timedelta(seconds=60 * 60 * 24),
    #     }
    #     token = jwt.encode(payload, SECRET_KEY)

    return jsonify({'msg': 'Login berhasil!'})
    # return jsonify({'result': 'success', 'token': token})
    # Case ketika kombinasi ID dan PW tidak ditemukan
    # else:
    #     return jsonify({'result': 'fail', 'msg': 'We could not find a user with that ID or password combination'})

@app.route('/update_password', methods=['POST'])
def update_password():
    username_receive = request.form['username_give']
    new_pw_receive = request.form['new_pw_give']
    
    return jsonify({'msg': 'Password Anda berhasil diubah!'})

@app.route('/sign_up', methods=['POST'])
def sign_up():
    nama_receive = request.form['nama_give']
    username_receive = request.form['username_give']
    email_receive = request.form['email_give']
    password_receive = request.form['password_give']
    
    return jsonify({'msg': 'Akun baru berhasil dibuat. Silahkan Login!'})

@app.route('/sign_up/cek-username', methods=['POST'])
def cek_username():
    username_receive = request.form.get('username_give')
    # exists = bool(db.users.find_one({'username': username_receive}))
    # return jsonify({'result': 'success', 'exists': exists})
    return jsonify({'msg': 'Username ini tersedia'})

@app.route('/laporUser', methods=['GET', 'POST'])
def lapor():
    if request.method == 'POST':
        # Handle POST Request here
        return render_template('lapor.html')
    return render_template('lapor.html')

@app.route('/userProfil', methods=['GET', 'POST'])
def userProfil():
    if request.method == 'POST':
        # Handle POST Request here
        return render_template('userProfil.html')
    return render_template('userProfil.html')

@app.route('/userProfil/edit-profil', methods=['POST'])
def editProfil():
    nama_receive = request.form['nama_give']
    deskBio_receive = request.form['deskBio_give']
    
    return jsonify({'msg': 'Profil Anda berhasil diupdate!'})

@app.route('/new-post', methods=['POST'])
def new_post():
    newPost_receive = request.form['new_post_give']
    
    return jsonify({'msg': 'Postingan baru berhasil ditambahkan!'})

@app.route('/tambah-komentar', methods=['POST'])
def tambah_komentar():
    komentar_receive = request.form['komentar_give']
    
    return jsonify({'msg': 'Komentar Anda berhasil ditambahkan!'})

@app.route("/delete-post", methods=["POST"])
def delete_post():
    # num_receive = request.form['num_give']
    # db.bucket.delete_one({ 'num': int(num_receive) })
    return jsonify({'msg': 'Postingan Anda berhasil dihapus!'})

@app.route('/forumBase', methods=['GET', 'POST'])
def forum():
    if request.method == 'POST':
        # Handle POST Request here
        return render_template('forum.html')
    return render_template('forum.html')

@app.route('/artikelBase', methods=['GET', 'POST'])
def artikel():
    if request.method == 'POST':
        # Handle POST Request here
        return render_template('artikel.html')
    return render_template('artikel.html')


# 
# 
# Admin function Here, Jangan Di-edit Push dan commit apabila Masih terjadi Eror!
# 
# 
@app.route('/loginPetugasSatgas', methods=['GET', 'POST'])
def loginAdmin():
    
    token_receive = request.cookies.get('token')
    if token_receive:
        try:
            payload = jwt.decode(token_receive, SECRET_KEY, algorithms=["HS256"])
            return redirect(url_for('adminDashboard'))
        except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
            pass  

    
    if request.method == 'POST':
        username_receive = request.form.get('username_give')
        password_receive = request.form.get('password_give')
        pw_hash = hashlib.sha256(password_receive.encode('utf-8')).hexdigest()
        result = db.admin.find_one({
            'username': username_receive,
            'password': pw_hash,
        })
        
        if result:
            role = result.get('role')
            payload = {
                'id': username_receive,
                'role': role,
                'exp': datetime.utcnow() + timedelta(seconds=60 * 60),
            }
            token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
            
            # Simpan role dalam sesi
            session['role'] = role
            
            # Create a redirect response and add a cookie to it
            response = make_response(redirect(url_for('adminDashboard')))
            response.set_cookie('token', token)
            
            return response
        else:
            flash("Username atau Password Salah!")
            return redirect(url_for("loginAdmin"))
 
    return render_template('admin/loginAdmin.html')

@app.route('/logOutPetugas', methods=['GET', 'POST'])
def logoutPetugas():
    response = make_response(redirect(url_for('loginAdmin')))
    response.set_cookie('token', '', expires=0)
    return response      
    

@app.route('/adminDashboard', methods=['GET', 'POST'])
def adminDashboard():
    token_receive = request.cookies.get('token')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=["HS256"])
        user_info = db.admin.find_one({"username": payload["id"]})
        dataAdmin = list(db.admin.find({"role": "Admin"}))
       
        return render_template('admin/adminDashboard.html',data=user_info , data_admin = dataAdmin)
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
         
        return redirect(url_for("loginAdmin", msg="Anda Belum Login"))
    
    
@app.route('/adminControl', methods=['GET', 'POST'])
def adminControl():
    if request.method == 'POST':
        adminName_receive = request.form.get('adminName_give')
        adminUsername_receive = request.form.get('adminUsername_give')
        adminPassword_receive = request.form.get('adminPassword_give')
        password_hash = hashlib.sha256(adminPassword_receive.encode('utf-8')).hexdigest()
        adminStatus_receive = request.form.get('adminStatus_give')
        
        data = {
            "nama": adminName_receive,
            "username": adminUsername_receive,
            "password": password_hash,
            "status": adminStatus_receive,
            "role": "admin"
        }
        # duplicate username check
        if db.admin.find_one({"username": adminUsername_receive}):
            flash("Username sudah terdaftar!")
            return redirect(url_for("adminControl"))
        else:         
            db.admin.insert_one(data)      
        # Handle POST Request here
        return redirect(url_for('adminControl'))
    token_receive = request.cookies.get('token')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=["HS256"])
        user_info = db.admin.find_one({"username": payload["id"]})
        dataAdmin = list(db.admin.find({"role": "admin"})) 
        return render_template('admin/adminControl.html',data=user_info , data_admin = dataAdmin)
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for("loginAdmin", msg="Anda Belum Login"))
    
@app.route('/adminControl/update', methods=['POST'])
def updateAdmin():
    adminName_receive = request.form.get('adminName_give')
    adminUsername_receive = request.form.get('adminUsername_give')
    adminPassword_receive = request.form.get('adminPassword_give')
    password_hash = hashlib.sha256(adminPassword_receive.encode('utf-8')).hexdigest()
    adminStatus_receive = request.form.get('adminStatus_give')
    
    update_fields = {}

    if adminName_receive != "":
        update_fields["nama"] = adminName_receive

    if adminUsername_receive != "":
        update_fields["username"] = adminUsername_receive

    if adminStatus_receive != "":
        update_fields["status"] = adminStatus_receive

    if adminPassword_receive != "":
        update_fields["password"] = password_hash

    db.admin.update_one(
        {"username": adminUsername_receive},
        {"$set": update_fields}
    )

    return redirect(url_for('adminControl'))

@app.route('/adminControl/delete/<username>', methods=['GET'])
def deleteAdmin(username):
    db.admin.delete_one({"username": username})
    return redirect(url_for('adminControl'))

# Menu admin kepada User

@app.route('/adminDashboard/detailLaporan', methods=['GET', 'POST'])
def detailLaporan():
    token_receive = request.cookies.get('token')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=["HS256"])
        user_info = db.admin.find_one({"username": payload["id"],
                                        "role": payload["role"]
                                        })
        return render_template('admin/detailLaporan.html',data=user_info)
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for("loginAdmin", msg="Anda Belum Login"))
        
        
@app.route('/adminDashboard/forumControl', methods=['GET', 'POST'])
def forumControl():
    token_receive = request.cookies.get('token')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=["HS256"])
        user_info = db.admin.find_one({"username": payload["id"],
                                        "role": payload["role"]
                                        })
        return render_template('admin/detailLaporan.html',data=user_info)
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for("loginAdmin", msg="Anda Belum Login"))
    
    
@app.route('/adminDashboard/userControl', methods=['GET', 'POST'])
def userControl():
        token_receive = request.cookies.get('token')
        try:
            payload = jwt.decode(token_receive, SECRET_KEY, algorithms=["HS256"])
            user_info = db.admin.find_one({"username": payload["id"],
                                           "role": payload["role"]
                                           })
            return render_template('admin/detailLaporan.html',data=user_info)
        except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
            return redirect(url_for("loginAdmin", msg="Anda Belum Login"))

@app.route('/adminDashboard/artikelControl', methods=['GET', 'POST'])
def artikelControl():
        token_receive = request.cookies.get('token')
        try:
            payload = jwt.decode(token_receive, SECRET_KEY, algorithms=["HS256"])
            user_info = db.admin.find_one({"username": payload["id"],
                                           "role": payload["role"]
                                           })
            return render_template('admin/detailLaporan.html',data=user_info)
        except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
            return redirect(url_for("loginAdmin", msg="Anda Belum Login"))

if __name__ == '__main__':
    #DEBUG is SET to TRUE. CHANGE FOR PROD
    app.run("0.0.0.0", port=5000, debug=True)
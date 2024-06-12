from pymongo import MongoClient
from datetime import datetime
import jwt
import datetime
import hashlib
from flask import Flask, render_template, jsonify, request, redirect, url_for, make_response, flash, session
from bson import ObjectId
from werkzeug.utils import secure_filename
import os
from os.path import join, dirname
from datetime import datetime, timedelta, timezone
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
@app.route('/',methods=['GET'])
def home():
    token_receive = request.cookies.get('mytoken')
    user_info = None
    print(token_receive)

    if token_receive:
        try:
            payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
            user_info = db.users.find_one({'username': payload.get('id')})

        except jwt.ExpiredSignatureError:
            msg = 'Akun Anda telah keluar, silahkan Login kembali!'
            flash(msg)

        except jwt.exceptions.DecodeError:
            msg = 'Maaf Kak, sepertinya ada masalah. Silahkan Login kembali!'
            flash(msg)

    return render_template('index.html', user_info=user_info)

# User Function Here!!!
@app.route('/loginUser', methods=['GET', 'POST'])
def loginUser():
    token_receive = request.cookies.get('mytoken')
    print (token_receive)

    if token_receive:
        try:
            payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
            user_info = db.users.find_one({'username': payload.get('id')})

            if user_info:
                return redirect(url_for('home'))

        except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
            pass

    if request.method == 'POST':
        # Handle POST Request here
        pass
    return render_template('login.html')

@app.route('/sign_in', methods=['POST'])
def sign_in():
    username_receive = request.form.get('username_give')
    password_receive = request.form.get('password_give')
    pw_hash = hashlib.sha256(password_receive.encode('utf-8')).hexdigest()
    
    result = db.users.find_one({
        'username': username_receive,
        'password': pw_hash,
    })
    if result:
        payload = {
            'id': username_receive,
            # Token bisa berlaku sampai 24 jam
            'exp': datetime.now(timezone.utc) + timedelta(seconds=60 * 60 * 24),
        }
        token = jwt.encode(payload, SECRET_KEY)
        
        # Membuat response
        response = make_response(jsonify({'result': 'success', 'msg': 'Anda berhasil Login!'}))
        # Mengatur cookie
        response.set_cookie('mytoken', token, httponly=True, samesite='Strict', path='/')
        return response
    
    # Case ketika kombinasi ID dan PW tidak ditemukan
    else:
        print(f"Login gagal untuk user {username_receive}.")
        return jsonify({'result': 'fail', 'msg': 'Maaf Kak, akun tidak ditemukan!'})

@app.route('/sign_out', methods=['GET', 'POST'])
def sign_out():
    response = make_response(redirect(url_for('home')))
    response.set_cookie('mytoken', '', expires=0)
    return response

@app.route('/update_password', methods=['POST'])
def update_password():
    try:
        username_receive = request.form['username_give']
        new_pw_receive = request.form['new_pw_give']
        new_pw_hash = hashlib.sha256(new_pw_receive.encode('utf-8')).hexdigest()
        
        filter = {'username': username_receive}
        new_pw = {'$set': {'password': new_pw_hash}}
        
        result = db.users.update_one(filter, new_pw)
        
        if result.matched_count > 0:
            return jsonify({'result': 'success', 'msg': 'Password Anda berhasil diubah!'})
        else:
            return jsonify({'result': 'fail', 'msg': 'User tidak ditemukan!'})
    except Exception as e:
        return jsonify({'result': 'fail', 'msg': str(e)})

@app.route('/sign_up', methods=['POST'])
def sign_up():
    nama_receive = request.form['nama_give']
    username_receive = request.form['username_give']
    email_receive = request.form['email_give']
    password_receive = request.form['password_give']
    password_hash = hashlib.sha256(password_receive.encode('utf-8')).hexdigest()
    
    db.users.insert_one({
        'nama lengkap': nama_receive,
        'username': username_receive,
        'email': email_receive,
        'password': password_hash,
        })
    
    return jsonify({'result': 'success'})

@app.route('/sign_up/cek-username', methods=['POST'])
def cek_username():
    username_receive = request.form.get('username_give')
    exists = bool(db.users.find_one({'username': username_receive}))

    return jsonify({'result': 'success', 'exists': exists})

@app.route('/laporUser', methods=['GET', 'POST'])
def lapor():
    if request.method == 'POST':
        # Handle POST Request here
        return render_template('lapor.html')
    return render_template('lapor.html')

@app.route('/userProfil', methods=['GET', 'POST'])
def userProfil():
    token_receive = request.cookies.get('mytoken')

    if not token_receive:
        msg = 'Anda harus login untuk mengakses halaman ini!'
        flash(msg)
        return redirect(url_for('home'))

    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        user_info = db.users.find_one({'username': payload.get('id')})

        if request.method == 'POST':
            # Handle POST Request here
            return render_template('userProfil.html', user_info=user_info)

        return render_template('userProfil.html', user_info=user_info)

    except jwt.ExpiredSignatureError:
        msg = 'Akun Anda telah keluar, silahkan Login kembali!'
        flash(msg)
        return redirect(url_for('home'))

    except jwt.exceptions.DecodeError:
        msg = 'Maaf Kak, sepertinya ada masalah. Silahkan Login kembali!'
        flash(msg)
        return redirect(url_for('home'))

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
        pass

# validasi token, apabila user sudah login maka akan menampilkan halaman forum
    token_receive = request.cookies.get('mytoken')
    if not token_receive:
        flash("Anda Belum Login")
        return redirect(url_for('loginUser'))

    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        user_info = db.users.find_one({"username": payload["id"]})
        if not user_info:
            raise jwt.exceptions.DecodeError
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        flash("Login tidak valid atau telah kadaluwarsa. Silakan login kembali.")
        return redirect(url_for('login_page'))

    return render_template('forum.html', username=user_info['username'])



@app.route('/artikelBase', methods=['GET', 'POST'])
def artikel():
    articles = list(db.article.find({}))
    for art in articles:
        print("Original Image Path:", art.get("gambar"))  # Debug print
        art["gambar"] = art.get("gambar")  # Just pass the image path directly
        print("Processed Image Path:", art.get("gambar"))  # Debug print
        print("Article Date:", art.get("date"))    # Debug print
        # Jika tanggal artikel belum ada, tambahkan tanggal saat ini
        if "date" not in art:
            art["date"] = datetime.now().strftime("%Y-%m-%d")
            print("Added Current Date:", art.get("date"))  # Debug print
    return render_template('artikel.html', articles=articles)






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
        if payload.get('role') != 'admin' and payload.get('role') != 'superAdmin':
            return redirect('/')
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
        if payload.get('role') != 'admin' and payload.get('role') != 'superAdmin':
            return redirect('/')
        user_info = db.admin.find_one({"username": payload["id"]})
        dataAdmin = db.admin.find({"role": "admin"})
        return render_template('admin/adminControl.html',data=user_info , data_admin = dataAdmin )
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
        if payload.get('role') != 'admin' and payload.get('role') != 'superAdmin':
            return redirect('/')
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
        if payload.get('role') != 'admin' and payload.get('role') != 'superAdmin':
            return redirect('/')
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
            if payload.get('role') != 'admin' and payload.get('role') != 'superAdmin':
                return redirect('/')
            user_info = db.admin.find_one({"username": payload["id"],
                                           "role": payload["role"]
                                           })
            # fetch data user from db.users
            dataUser = list(db.users.find())   
            return render_template('admin/adminUserControl.html',data=user_info, data_user = dataUser )     
        except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
            return redirect(url_for("loginAdmin", msg="Anda Belum Login"))



@app.route('/adminDashboard/deleteArticle/<article_id>', methods=['POST'])
def delete_article(article_id):
    try:
        db.article.delete_one({"_id": ObjectId(article_id)})
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# Admin - Edit Article
@app.route('/adminDashboard/editArticle/<article_id>', methods=['POST'])
def edit_article(article_id):
    try:
        title_receive = request.form["judulArtikel_give"]
        isi_receive = request.form["isiArtikel_give"]
        date_receive = request.form["dateArtikel_give"]

        # Mendapatkan tanggal dan waktu saat ini
        current_datetime = datetime.now()
        date_time = current_datetime.strftime("%Y-%m-%d-%H-%M-%S")

        update_data = {
            "title": title_receive,
            "isi": isi_receive,
            "date": date_receive,
        }

        if 'gambarArtikel_give' in request.files:
            gambar_receive = request.files["gambarArtikel_give"]
            if gambar_receive.filename != '':
                extensiongambar = gambar_receive.filename.split('.')[-1]
                save_dir = os.path.join(app.root_path, 'static/adminAsset/articleImage/')
                os.makedirs(save_dir, exist_ok=True)
                save_gambar = f'/static/adminAsset/articleImage/{date_time}.{extensiongambar}'
                gambar_receive.save(os.path.join(save_dir, f'image{date_time}.{extensiongambar}'))
                update_data['gambar'] = save_gambar

        db.article.update_one({"_id": ObjectId(article_id)}, {"$set": update_data})
        return redirect(url_for('artikelControl'))
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/adminDashboard/artikelControl', methods=['GET', 'POST'])
def artikelControl():
    if request.method == 'POST':
        title_receive = request.form["judulArtikel_give"]
        isi_receive = request.form["isiArtikel_give"]
        
        today = datetime.now()
        date_time = today.strftime("%Y-%m-%d-%H-%M-%S")
        
        gambar_receive = request.files["gambarArtikel_give"]
        extensiongambar = gambar_receive.filename.split('.')[-1]
        save_dir = os.path.join(app.root_path, 'static/adminAsset/articleImage/')
        os.makedirs(save_dir, exist_ok=True)  # Create directory if not exists
        filename = f'image{date_time}.{extensiongambar}'
        save_gambar = os.path.join('adminAsset/articleImage/', filename)  # Relative path without '/static/'
        gambar_receive.save(os.path.join(save_dir, filename))
        
        thisdate = today.strftime("%Y-%m-%d")

        doc = {
            'title': title_receive,
            'gambar': save_gambar,
            'isi': isi_receive,
            'date': thisdate  # Tambahkan tanggal saat ini ke dalam dokumen artikel
        }
        db.article.insert_one(doc)
        return redirect(url_for('artikelControl'))

    token_receive = request.cookies.get('token')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=["HS256"])
        if payload.get('role') not in ['admin', 'superAdmin']:
            return redirect('/')
        user_info = db.admin.find_one({"username": payload["id"], "role": payload["role"]})
        articles = list(db.article.find())

        return render_template('admin/artikelControl.html', data=user_info, articles=articles)
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for("loginAdmin", msg="Anda Belum Login"))

if __name__ == '__main__':
    #DEBUG is SET to TRUE. CHANGE FOR PROD
    app.run("0.0.0.0", port=5000, debug=True)


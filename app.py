from pymongo import MongoClient
from datetime import datetime
import jwt
import hashlib
from flask import Flask, render_template, jsonify, request, redirect, url_for, make_response, flash, session
from bson import ObjectId
from werkzeug.utils import secure_filename
import os   
from os.path import join, dirname
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from html import escape
import re
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)

MONGODB_URI = os.environ.get("MONGODB_URI")
DB_NAME =  os.environ.get("DB_NAME")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD")

client = MongoClient(MONGODB_URI)

db = client[DB_NAME]

SECRET_KEY = os.environ.get("SECRET_KEY")

app=Flask(__name__)
# SMTP email configuration for Resi Pengaduan

def send_email(resi,nama,program_studi,detail_report,tanggal_kejadian,lokasi_kejadian, recipient):
    # Setup the SMTP server and login
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login("rafaelsiregar611@gmail.com", EMAIL_PASSWORD)

    # Create the message
    msg = MIMEMultipart()
    msg['From'] = "rafaelsiregar611@gmail.com"
    msg['To'] = recipient
    msg['Subject'] = "Resi Pelaporan"
    body = f"""
        Berikut adalah detail laporan Anda:
        
        No Resi: {resi}
        Nama Pelapor: {nama}
        Program Studi: {program_studi}
        Detail Laporan: {detail_report}
        Tanggal Kejadian: {tanggal_kejadian.strftime('%Y-%m-%d')}
        Lokasi Kejadian: {lokasi_kejadian}

        Terima kasih telah melakukan pelaporan.Tim Satgas Akan Segera Melakukan Peninjauan terhadap Laporan Anda.
        """
    msg.attach(MIMEText(body, 'plain'))

    # Send the message
    text = msg.as_string()
    server.sendmail("rafaelsiregar611@gmail.com", recipient, text)
    server.quit()

# 
app.secret_key = os.environ.get("SECRET_KEY")
# Index / Landing Page!
@app.route('/',methods=['GET'])
def home():
    token_receive = request.cookies.get('mytoken')
    user_info = None

    if token_receive:
        try:
            payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
            user_info = db.mahasiswa.find_one({'nim': payload.get('id')})

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

    if token_receive:
        try:
            payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
            user_info = db.mahasiswa.find_one({'nim': payload.get('id')})

            if user_info:
                return redirect(url_for('home'))

        except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
            pass

    if request.method == 'POST':
        # Handle POST Request here
        pass

    # If user is already logged in, redirect to home
    if 'nim' in session:
        return redirect(url_for('home'))

    return render_template('login.html')

@app.route('/sign_in', methods=['POST'])
def sign_in():
    nim_receive = request.form.get('nim-give')
    password_receive = request.form.get('password_give')
    pw_hash = hashlib.sha256(password_receive.encode('utf-8')).hexdigest()
    
    result = db.mahasiswa.find_one({
        'nim': nim_receive,
    })

    if result:
        password_new = result.get('password_new')
        default_password = result.get('default_password', '')
        if password_new is None :   
            if default_password == pw_hash:   
                session['nim'] = nim_receive
                return redirect(url_for('verifikasi', nim=nim_receive))
            else:
                msg = flash("Password Salah!")         
                return redirect(url_for("loginUser",msg = msg))
        elif password_new == pw_hash:  # Jika password_new ditemukan dan sesuai dengan inputan user
            payload = {
                'id': nim_receive, # Menggunakan NIM sebagai id
                'exp': datetime.now(timezone.utc) + timedelta(seconds=60 * 60 * 24),
            }
            token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')            
            response = make_response(redirect(url_for('home')))
            response.set_cookie('mytoken', token)
            flash('Anda berhasil login', 'success')
            return response
        else:
            msg = flash("Password Salah!","error")         
            return redirect(url_for("loginUser",msg = msg))
    else:
        msg = flash("NIM atau Password Salah!","error")         
        return redirect(url_for("loginUser",msg = msg))
    
@app.route('/verifikasiLogin/<nim>', methods=['GET', 'POST'])
def verifikasi(nim):
    if 'nim' not in session or session['nim'] != nim:
        # Jika tidak, kembalikan ke halaman login atau tampilkan pesan error
        return redirect(url_for('loginUser'))

    mahasiswa = db.mahasiswa.find_one({'nim': nim})

    if request.method == 'POST':
        # Ambil data dari form
        email_kampus = request.form.get('email-kampus-give')
        nama_ibu = request.form.get('nama-ibu')
        new_password = request.form.get('new-password')

        # Cek apakah email dan nama ibu benar
        if mahasiswa['email'] != email_kampus:
            flash('Email kampus salah', 'error')
        elif mahasiswa['nama_ibu'] != nama_ibu:
            flash('Nama ibu salah', 'error')
        else:
            # Jika semua data benar, update password
            pw_hash = hashlib.sha256(new_password.encode('utf-8')).hexdigest()
            db.mahasiswa.update_one({'nim': nim}, {'$set': {'password_new': pw_hash}})
            msg = flash('Verifikasi Berhasil', 'success')
            session.pop('nim', None)
            return redirect(url_for('loginUser', msg=msg))

    return render_template('loginVerifikasi.html', nim=nim, mahasiswa=mahasiswa)
    
    

@app.route('/sign_out', methods=['GET', 'POST'])
def sign_out():
    
    response = make_response(redirect(url_for('home')))
    response.set_cookie('mytoken', '', expires=0)
    flash('Anda telah keluar', 'success')
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


@app.route('/laporUser', methods=['GET', 'POST'])
def lapor():
    if request.method == 'POST':
        email= request.form.get('emailPelapor')
        no_resi = request.form.get('noResi')
        nama_pelapor = request.form.get('namaPelapor')
        program_studi = request.form.get('programStudi')
        detail_report = request.form.get('detailReport')
        tanggal_kejadian = datetime.strptime(request.form.get('tanggalKejadian'), '%Y-%m-%d')
        lokasi_kejadian = request.form.get('lokasiKejadian')
        
        data = {
            'email': email,
            'no_resi': no_resi,
            'nama_pelapor': nama_pelapor,
            'program_studi': program_studi,
            'detail_report': detail_report,
            'tanggal_kejadian': tanggal_kejadian,
            'lokasi_kejadian': lokasi_kejadian,
            'status': 'Dalam Antirian'
        }
        db.pelaporan.insert_one(data)
         # Send the email.
        send_email(no_resi,nama_pelapor,program_studi,detail_report,tanggal_kejadian,lokasi_kejadian, email)
        return redirect(url_for('lapor'))
    token_receive = request.cookies.get('mytoken')
    user_info = None
    if token_receive:
        try:
            payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
            user_info = db.mahasiswa.find_one({'nim': payload.get('id')})

        except jwt.ExpiredSignatureError:
            msg = 'Akun Anda telah keluar, silahkan Login kembali!'
            flash(msg)

        except jwt.exceptions.DecodeError:
            msg = 'Maaf Kak, sepertinya ada masalah. Silahkan Login kembali!'
            flash(msg)
    return render_template('lapor.html',user_info=user_info)

#Rute untuk mengarahkan user ke profilnya
#Rute untuk menampilkan profil user berdasarkan nim nya
@app.route('/userProfil', methods=['GET', 'POST'])
def userProfil():
    token_receive = request.cookies.get('mytoken')
    if not token_receive:
        msg = flash('Anda Belum Login','error')
        return redirect(url_for('home', msg=msg))

    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        nim = payload.get('id')
        user_info = db.mahasiswa.find_one({'nim': nim}, {'_id': False})
        status = nim == payload.get('id')
        
        # Hanya ambil postingan dari user yang sedang login
        postingan = list(db.postingan.find({'nim': nim}))
        for post in postingan:
            post['id'] = str(post['_id'])
            mahasiswa_info = db.mahasiswa.find_one({"nim": post['nim']})
            post['nama'] = mahasiswa_info['nama']
            post['email'] = mahasiswa_info['email']
            
            # get comment count
            comments = list(db.comments.find({'post_id': ObjectId(post['id'])}))
            # Add the comment count to the post
            post['comment_count'] = comments
        
        if request.method == 'POST':
            # Handle POST Request here
            return render_template('userProfil.html', user_info=user_info)

        return render_template('userProfil.html', user_info=user_info, postingan=postingan, status=status)

    except jwt.ExpiredSignatureError:
        flash('Akun Anda telah keluar, silahkan Login kembali!')
        return redirect(url_for('home'))

    except jwt.exceptions.DecodeError:
        flash('Maaf Kak, sepertinya ada masalah. Silahkan Login kembali!')
        return redirect(url_for('home'))

@app.route('/userProfil/password-update', methods=['POST'])
def editProfil():
    passwordLamaReceive = escape(request.form['passwordLamaGive'])
    passwordBaruReceive = escape(request.form['passwordBaruGive'])

    # Remove any non-word characters
    passwordLamaReceive = re.sub(r'\W', '', passwordLamaReceive)
    passwordBaruReceive = re.sub(r'\W', '', passwordBaruReceive)

    passwordBaruHash = hashlib.sha256(passwordBaruReceive.encode('utf-8')).hexdigest()
    passwordLamaHash = hashlib.sha256(passwordLamaReceive.encode('utf-8')).hexdigest()
    token_receive = request.cookies.get('mytoken')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        nim = payload.get('id')
        user_info = db.mahasiswa.find_one({'nim': nim})
        if user_info['password_new'] == passwordLamaHash:
            db.mahasiswa.update_one({'nim': nim}, {'$set': {'password_new': passwordBaruHash}})
            msg = flash('Password berhasil diubah!','success')
            return redirect(url_for('userProfil', msg=msg))
        else:
            msg = flash('Password lama salah!','error')
            return redirect(url_for('userProfil', msg=msg))
    except Exception as e:
        msg = flash('Terjadi kesalahan, silahkan coba lagi!','error')
        return redirect(url_for('home', msg=msg))
    

@app.route('/new-post', methods=['GET', 'POST'])
def new_post():
    # validasi token, apabila user sudah login maka akan menampilkan halaman forum
    token_receive = request.cookies.get('mytoken')
    if not token_receive:
        flash("Anda Belum Login", "error")
        return redirect(url_for('loginUser'))

    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        user_info = db.mahasiswa.find_one({"nim": payload["id"]})
        if not user_info:
            raise jwt.exceptions.DecodeError
        
        if request.method == 'POST':
        # Handle POST Request here
            user_post_receive = escape(request.form['user-post-give'])
            mahasiswa_get_nim = escape(user_info.get('nim'))
            data = {
                "nim": mahasiswa_get_nim,
                "post": user_post_receive,
                "date": datetime.now().strftime("%Y-%m-%d")
            }
            db.postingan.insert_one(data)
            return redirect(url_for('userProfil'))

    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        flash("Login tidak valid atau telah kadaluwarsa. Silakan login kembali.", "error")
        return redirect(url_for('loginUser'))

    return render_template('userProfil.html', user_info=user_info)

@app.route("/delete-post", methods=["POST"])
def delete_post():
    post_id_receive = request.form['post_id_give']
    db.postingan.delete_one({'_id': ObjectId(post_id_receive)})
    return jsonify({'msg': 'Postingan Anda berhasil dihapus!'})


@app.route('/forumBase', methods=['GET', 'POST'])
def forum():        
    # validasi token, apabila user sudah login maka akan menampilkan halaman forum
    token_receive = request.cookies.get('mytoken')
    if not token_receive:
        msg = flash("Anda Belum Login","error")
        return redirect(url_for('loginUser',msg=msg))
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        user_info = db.mahasiswa.find_one({"nim": payload["id"]})
         
        postingan = list(db.postingan.find())
        for post in postingan:
            post['id'] = str(post['_id'])
            mahasiswa_info = db.mahasiswa.find_one({"nim": post['nim']})
            post['nama'] = mahasiswa_info['nama']
            post['email']=mahasiswa_info['email']
             # Fetch comments related to the current post
            comments = list(db.comments.find({'post_id': ObjectId(post['id'])}))

            # Add the comment count to the post
            post['comment_count'] = comments
        if not user_info:
            raise jwt.exceptions.DecodeError
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        msg = flash("Login tidak valid atau telah kadaluwarsa. Silakan login kembali.","error")
        return redirect(url_for('loginUser', msg=msg))
    
    # jalan kan post untuk postingan ketika user sedang login
    if request.method == 'POST':
        # Handle POST Request here
        user_post_receive = escape(request.form['user-post-give'])
        mahasiswa_get_nim = escape(user_info.get('nim'))
        maahasiswa_get_nama = escape(user_info.get('nama'))
        data = {
            "nim": mahasiswa_get_nim,
            "post": user_post_receive,
            "date": datetime.now().strftime("%Y-%m-%d")
        }
        db.postingan.insert_one(data)
        flash(f'Postingan {maahasiswa_get_nama} berhasil ditambahkan!', 'success')
        return redirect(url_for('forum'))       

    # Anda bisa menambahkan kode untuk menangani user_post_receive di sini

    return render_template('forum.html', user_info=user_info, postingan = postingan)

@app.route('/postingan-detail/<idPost>', methods=['GET', 'POST'])
def detailPost(idPost):
    token_receive = request.cookies.get('mytoken')
    if token_receive : 
        try:
            payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
            user_info = db.mahasiswa.find_one({'nim': payload.get('id')})
            if not user_info:
                flash("User tidak ditemukan.", "error")
                return redirect(url_for('loginUser'))

            if request.method == 'POST':
                comment = request.form.get('comment')
                db.comments.insert_one({
                    'nim': user_info['nim'],
                    'post_id': ObjectId(idPost),
                    'comment': comment,
                    'date': datetime.utcnow()
                })
                flash("Komentar berhasil diposting.", "success")
                return redirect(url_for('detailPost', idPost=idPost))

            post = db.postingan.find_one({'_id': ObjectId(idPost)})
            post['id'] = str(post['_id'])
            mahasiswa_info = db.mahasiswa.find_one({"nim": post['nim']})
            post['nama'] = mahasiswa_info['nama']
            post['email'] = mahasiswa_info['email']

            # Fetch comments related to the current post
            comments = db.comments.find({'post_id': ObjectId(idPost)})
             
            # Convert comments to a list so it can be passed to the template
            comments = list(comments)
            for comment in comments:
                comment['id'] = str(comment['_id'])
                mahasiswa_info = db.mahasiswa.find_one({'nim': comment['nim']})
                comment['nama'] = mahasiswa_info['nama']

            return render_template('detailForum.html', post=post, user_info=user_info, comments=comments)
        except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
            flash("Login tidak valid atau telah kadaluwarsa. Silakan login kembali.","error")
            return redirect(url_for('loginUser'))
    else:
        flash("Token tidak ditemukan. Silakan login.","error")
        return redirect(url_for('loginUser'))

@app.route('/artikelBase', methods=['GET', 'POST'])
def artikel():
    token_receive = request.cookies.get('mytoken')
    user_info = None
    if token_receive:
        try:
            payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
            user_info = db.mahasiswa.find_one({'nim': payload.get('id')})

        except jwt.ExpiredSignatureError:
            msg = 'Akun Anda telah keluar, silahkan Login kembali!'
            flash(msg)

        except jwt.exceptions.DecodeError:
            msg = 'Maaf Kak, sepertinya ada masalah. Silahkan Login kembali!'
            flash(msg)
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
    return render_template('artikel.html', articles=articles, user_info=user_info)
 
@app.route('/like_post/<post_id>', methods=['POST'])
def like_post(post_id):
    # Fetch the post from the database
    post = db.postingan.find_one({'_id': ObjectId(post_id)})

    token_receive = request.cookies.get('mytoken')
    if not token_receive:
        flash("Anda Belum Login", "error")
        return redirect(url_for('loginUser'))

    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        user_info = db.mahasiswa.find_one({"nim": payload["id"]})
    except jwt.ExpiredSignatureError:
        flash("Session Anda telah berakhir, silakan login kembali", "error")
        return redirect(url_for('loginUser'))
    except jwt.InvalidTokenError:
        flash("Token Anda tidak valid, silakan login kembali", "error")
        return redirect(url_for('loginUser'))

    # If the 'likes' key doesn't exist in the post, create it and set it to an empty list
    if 'likes' not in post:
        post['likes'] = []

    if user_info['nim'] in post['likes']:
        # If the user has already liked the post, unlike it
        post['likes'].remove(user_info['nim'])
    else:
        # If the user has not liked the post, like it
        post['likes'].append(user_info['nim'])

    # Save the updated post back to the database
    db.postingan.update_one({'_id': ObjectId(post_id)}, {'$set': {'likes': post['likes']}})
    
    # Determine whether the user liked the post
    user_liked = user_info['nim'] in post['likes']

    # Return a JSON response
    return jsonify({'likes': post['likes'], 'userLiked': user_liked})



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
    session.clear()  # Menghapus semua data session
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

        # Mengambil statistik dari database
        article_count = db.article.count_documents({})
        postingan_count = db.postingan.count_documents({})
        mahasiswa_count = db.mahasiswa.count_documents({})
        pelaporan_count = db.pelaporan.count_documents({})

        return render_template('admin/adminDashboard.html', data=user_info, data_admin=dataAdmin, 
                               article_count=article_count, postingan_count=postingan_count, 
                               mahasiswa_count=mahasiswa_count, pelaporan_count=pelaporan_count)
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        msg = flash("Anda Belum Login")
        return redirect(url_for("loginAdmin", msg=msg))
    
    
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
        role = payload.get('role')
        if role == 'admin':
            return redirect('/adminDashboard')
        elif role != 'superAdmin':
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
        laporan_info = list(db.pelaporan.find())
        return render_template('admin/detailLaporan.html',data=user_info, laporan = laporan_info)
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
        postingan = list(db.postingan.find())
        for post in postingan:
            post['id'] = str(post['_id'])
            mahasiswa_info = db.mahasiswa.find_one({"nim": post['nim']})
            post['nama'] = mahasiswa_info['nama']
            post['email']=mahasiswa_info['email']
        return render_template('admin/forumControl.html',data=user_info,postingan = postingan)
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for("loginAdmin", msg="Anda Belum Login"))
    
    
@app.route('/adminDashboard/userControl', methods=['GET', 'POST'])
def userControl():
        if request.method == 'POST':
            mahasiswa_name = request.form.get('nama_mahasiswa_give')
            mahasiswa_email = request.form.get('email_mahasiswa_give')
            mahasiswa_nim = request.form.get('mahasiswa_nim_give')
            mahasiswa_prodi = request.form.get('prodi_mahasiswa_give')
            ibu_mahasiswa = request.form.get('ibu_mahasiswa_give')
            password_hash = hashlib.sha256(mahasiswa_nim.encode('utf-8')).hexdigest()
            
            data = {
                "nama": mahasiswa_name,
                "email": mahasiswa_email,
                "nim": mahasiswa_nim,
                "program_studi": mahasiswa_prodi,
                "nama_ibu": ibu_mahasiswa,
                "default_password": password_hash,
                "role": "mahasiswa"
            }
            # duplicate username check
            if db.mahasiswa.find_one({"nim": mahasiswa_nim}):
                flash("NIM sudah terdaftar!")
                return redirect(url_for("userControl"))
            else:         
                db.mahasiswa.insert_one(data)      
            # Handle POST Request here
            return redirect(url_for('userControl'))
    
        token_receive = request.cookies.get('token')
        try:
            payload = jwt.decode(token_receive, SECRET_KEY, algorithms=["HS256"])
            if payload.get('role') != 'admin' and payload.get('role') != 'superAdmin':
                return redirect('/')
            user_info = db.admin.find_one({"username": payload["id"],
                                           "role": payload["role"]
                                           })
            # fetch data user from db.users
            dataUser = list(db.mahasiswa.find())   
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


from pymongo import MongoClient
from datetime import datetime
import jwt
import hashlib
from flask import Flask, render_template, jsonify, request, redirect, url_for, make_response, flash, session
from bson import ObjectId
from werkzeug.utils import secure_filename
import os   
import bleach
from os.path import join, dirname
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
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
def send_email(resi, nama, program_studi, detail_report, tanggal_kejadian, lokasi_kejadian, recipient):
    server = smtplib.SMTP('smtp.gmail.com', 587) 
    try:
        server.starttls()
        server.login("rafaelsiregar116@gmail.com", "leyf oqai fovm ukwt")

        msg = MIMEMultipart()
        msg['From'] = "rafaelsiregar116@gmail.com"
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

            Terima kasih telah melakukan pelaporan. Tim Satgas Akan Segera Melakukan Peninjauan terhadap Laporan Anda.
            """
        msg.attach(MIMEText(body, 'plain'))

        text = msg.as_string()
        server.sendmail("rafaelsiregar116@gmail.com", recipient, text)
    finally:
        server.quit()

# 
app.secret_key = os.environ.get("SECRET_KEY")
# Index / Landing Page!
@app.route('/',methods=['GET'])
def home():
    if 'nim' in session:
        session.pop('nim', None)
    
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
        elif password_new == pw_hash:  
            payload = {
                'id': nim_receive, 
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
        return redirect(url_for('loginUser'))

    mahasiswa = db.mahasiswa.find_one({'nim': nim})

    if request.method == 'POST':
        email_kampus = request.form.get('email-kampus-give')
        nama_ibu = request.form.get('nama-ibu')
        new_password = request.form.get('new-password')

        # Cek apakah email dan nama ibu benar
        if mahasiswa['email'] != email_kampus:
            flash('Email kampus salah', 'error')
        elif mahasiswa['nama_ibu'] != nama_ibu:
            flash('Nama ibu salah', 'error')
        else:
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
        tanggal_melapor = datetime.now()
        lokasi_kejadian = request.form.get('lokasiKejadian')
        
        data = {
            'email': email,
            'no_resi': no_resi,
            'nama_pelapor': nama_pelapor,
            'program_studi': program_studi,
            'detail_report': detail_report,
            'tanggal_kejadian': tanggal_kejadian,
            'tanggal_melapor': tanggal_melapor,
            'lokasi_kejadian': lokasi_kejadian,
            'status': 'Dalam Antrian'
        }
        db.pelaporan.insert_one(data)
         # Send the email.
        send_email(no_resi,nama_pelapor,program_studi,detail_report,tanggal_kejadian,lokasi_kejadian, email)
        flash('Laporan Anda berhasil dikirim!', 'success')
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
        
        # tangkap informasi resi yang pernah di cek oleh user
        cek_laporan = db.cek_laporan.find({'nim': nim})
        no_resi = [resi['no_resi'] for resi in cek_laporan]
        if not no_resi:
            no_resi = []
        
        # Hanya ambil postingan dari user yang sedang login
        postingan = list(db.postingan.find({'nim': nim}))
        if not postingan:
            postingan = []
        else:
            for post in postingan:
                post['id'] = str(post['_id'])
                mahasiswa_info = db.mahasiswa.find_one({"nim": post['nim']})
                post['nama'] = mahasiswa_info['nama']
                post['email'] = mahasiswa_info['email']
                # get comment count
                comments = list(db.comments.find({'post_id': ObjectId(post['id'])}))
                # Add the comment count
                post['comment_count'] = comments
        
        # method Post pada userProfil
        ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
        def allowed_file(filename):
            return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
        if request.method == 'POST':
            if 'photo-new' not in request.files:
                flash('No file part', 'error')
                return redirect(request.url)
            photo_receive = request.files['photo-new']
            if photo_receive.filename == '':
                flash('No selected file', 'error')
                return redirect(request.url)
            if photo_receive and allowed_file(photo_receive.filename):
                photo_receive_name = secure_filename(photo_receive.filename)
                photo_receive_extension = photo_receive_name.rsplit('.', 1)[1].lower()
                photo_saveto = f'static/foto_profil/{nim}.{photo_receive_extension}'
                upload_to_file = os.path.join(app.root_path, photo_saveto)
                try:                    
                    old_photo_path = os.path.join(app.root_path, 'static', user_info.get('fotoProfile', ''))                  
                    default_photo = 'foto_profil/Default-profile-image.png'  
                    if os.path.isfile(old_photo_path) and old_photo_path != os.path.join(app.root_path, default_photo):
                        os.remove(old_photo_path)
                        photo_receive.save(upload_to_file)
                    db.mahasiswa.update_one({'nim': nim}, {'$set': {'fotoProfile': f'foto_profil/{nim}.{photo_receive_extension}'}})
                    flash('Foto Profil berhasil diubah!', 'success')
                except Exception as e:
                    flash(f'An error occurred: {e}', 'error')
            else:
                flash('Invalid file type', 'error')
            return redirect(url_for('userProfil'))

        return render_template('userProfil.html', user_info=user_info, postingan=postingan, status=status, no_resi=no_resi)

    except jwt.ExpiredSignatureError:
        flash('Akun Anda telah keluar, silahkan Login kembali!')
        return redirect(url_for('home'))

    except jwt.exceptions.DecodeError:
        flash('Maaf Kak, sepertinya ada masalah. Silahkan Login kembali!')
        return redirect(url_for('home'))

@app.route('/userProfil/password-update', methods=['POST'])
def editProfil():
    passwordLamaReceive = bleach.clean(request.form['passwordLamaGive'])
    passwordBaruReceive = bleach.clean(request.form['passwordBaruGive'])

    # Lakukan Sanitasi inputan usaer
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
            user_post_receive = bleach.clean(request.form['user-post-give'])
            mahasiswa_get_nim = bleach.clean(user_info.get('nim'))
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
            comments = list(db.comments.find({'post_id': ObjectId(post['id'])})) 
            post['comment_count'] = comments
            if 'fotoProfile' in mahasiswa_info and mahasiswa_info['fotoProfile']:
                post['fotoProfile'] = mahasiswa_info['fotoProfile']
            else:
                continue 
            
        if not user_info:
            raise jwt.exceptions.DecodeError
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        msg = flash("Login tidak valid atau telah kadaluwarsa. Silakan login kembali.","error")
        return redirect(url_for('loginUser', msg=msg)) 
    if request.method == 'POST': 
        user_post_receive = bleach.clean(request.form['user-post-give'])
        mahasiswa_get_nim = bleach.clean(user_info.get('nim'))
        mahasiswa_get_nama = bleach.clean(user_info.get('nama'))  # Memperbaiki typo pada variabel
        data = {
            "nim": mahasiswa_get_nim,
            "post": user_post_receive,
            "date": datetime.now().strftime("%Y-%m-%d")
        }
        db.postingan.insert_one(data)
        flash(f'Postingan {mahasiswa_get_nama} berhasil ditambahkan!', 'success')
        return redirect(url_for('forum'))      
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
                comment = bleach.clean(request.form['comment'])
                db.comments.insert_one({
                    'nim': user_info['nim'],
                    'post_id': ObjectId(idPost),
                    'comment': comment,
                    'date': datetime.utcnow()
                })
                flash("Komentar berhasil diposting.", "success")
                return redirect(url_for('detailPost', idPost=idPost))
            
            comments = db.comments.find({'post_id': ObjectId(idPost)})
            post = db.postingan.find_one({'_id': ObjectId(idPost)})
            post['id'] = str(post['_id'])
            mahasiswa_info = db.mahasiswa.find_one({"nim": post['nim']})
            post['nama'] = mahasiswa_info['nama']
            post['email'] = mahasiswa_info['email'] 
            if 'fotoProfile' in mahasiswa_info and mahasiswa_info['fotoProfile']:
                post['fotoProfile'] = mahasiswa_info['fotoProfile'] 
            comments = list(comments)
            for comment in comments:
                comment['id'] = str(comment['_id'])
                mahasiswa_info = db.mahasiswa.find_one({'nim': comment['nim']})
                comment['nama'] = mahasiswa_info['nama'] 
                if 'fotoProfile' in mahasiswa_info and mahasiswa_info['fotoProfile']:
                    comment['fotoProfile'] = mahasiswa_info['fotoProfile']        
            return render_template('detailForum.html', post=post, user_info=user_info, comments=comments)
        except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
            flash("Login tidak valid atau telah kadaluwarsa. Silakan login kembali.","error")
            return redirect(url_for('loginUser'))
    else:
        flash("Token tidak ditemukan. Silakan login.","error")
        return redirect(url_for('loginUser'))

@app.route('/delete-comment/<commentId>', methods=['POST'])
def delete_comment(commentId):
    try:
        db.comments.delete_one({'_id': ObjectId(commentId)})
        flash("Komentar berhasil dihapus.", "success")
        return jsonify({"success": True, "message": "Komentar berhasil dihapus."}), 200
    except Exception as e:
        flash("Gagal menghapus komentar.", "error")
        return jsonify({"success": False, "message": "Gagal menghapus komentar."}), 500
    
@app.route('/edit_comment/<commentId>', methods=['POST'])
def editcomment(commentId):
    try:
        # Sanitasi input
        comment = bleach.clean(request.form['commentOld'])      
       
        # Update database
        db.comments.update_one({'_id': ObjectId(commentId)}, {'$set': {'comment': comment}})
        flash("Komentar berhasil diubah.", "success")
        return redirect(request.referrer)
    except Exception as e:
        flash(f"Gagal mengubah komentar: {str(e)}", "error")
        return redirect(request.referrer), 500   


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
        art["gambar"] = art.get("gambar")
        if "date" not in art:
            art["date"] = datetime.now().strftime("%Y-%m-%d") 
    return render_template('artikel.html', articles=articles, user_info=user_info)

@app.route('/detail-artikel/<idArtikel>', methods=['GET', 'POST'])
def detailArtikel(idArtikel):
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
    article = db.article.find_one({'_id': ObjectId(idArtikel) })
    return render_template('detailArtikel.html', user_info=user_info, article=article)
 
@app.route('/like_post/<post_id>', methods=['POST'])
def like_post(post_id): 
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
    if 'likes' not in post:
        post['likes'] = []

    if user_info['nim'] in post['likes']: 
        post['likes'].remove(user_info['nim'])
    else: 
        post['likes'].append(user_info['nim'])
 
    db.postingan.update_one({'_id': ObjectId(post_id)}, {'$set': {'likes': post['likes']}})
    
    user_liked = user_info['nim'] in post['likes']

    return jsonify({'likes': post['likes'], 'userLiked': user_liked})

@app.route('/cekLaporan', methods=['POST'])
def cekLaporanbyResi():
    token_receive = request.cookies.get('mytoken')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256']) 
        if not payload:
            flash("Anda Belum Login", "error")
            return redirect(url_for('loginUser'))
    except jwt.ExpiredSignatureError:
        flash("Session Anda telah berakhir, silakan login kembali", "error")
        return redirect(url_for('loginUser'))
    except jwt.InvalidTokenError:
        flash("Token Anda tidak valid, silakan login kembali", "error")
        return redirect(url_for('loginUser')) 
    user_checker = db.mahasiswa.find_one({'nim': payload.get('id')})
    no_resi = request.form.get('resiLaporan-give') 
    existing_check = db.cek_laporan.find_one({'nim': user_checker['nim'], 'no_resi': no_resi}) 
    if not existing_check:
            insert_into_koleksi_check = {
            'nim': user_checker['nim'],
            'no_resi': no_resi,
            'date': datetime.now()
            }
            db.cek_laporan.insert_one(insert_into_koleksi_check)
     
    data = db.pelaporan.find_one({'no_resi': no_resi})
    status_laporan = data.get('status') if data else None
    if data:
        flash(f"Status Laporan Anda: {status_laporan} ", "success")
        return redirect(url_for('userProfil'))
    else:
        flash('No Resi tidak ditemukan', 'error')
        return redirect(url_for('userProfil'))


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
            session['role'] = role 
            flash("Anda berhasil login", "success")
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
    flash('Anda telah keluar', 'success')
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
        summary_pelaporan_byMonth = {}
        summary_pelaporan_byYear = {}
        if db.pelaporan.count_documents({}) > 0:
            sort_pelporan_byMonth = db.pelaporan.aggregate([
                {
                    '$group': {
                        '_id': {'$month': '$tanggal_melapor'},
                        'count': {'$sum': 1}
                    }
                }
            ])
            for data in sort_pelporan_byMonth:
                summary_pelaporan_byMonth[data['_id']] = data['count']
            sort_pelporan_byYear = db.pelaporan.aggregate([
                {
                    '$group': {
                        '_id': {'$year': '$tanggal_melapor'},
                        'count': {'$sum': 1}
                    }
                }
            ])
            for data in sort_pelporan_byYear:
                summary_pelaporan_byYear[data['_id']] = data['count']
        
        return render_template('admin/adminDashboard.html', data=user_info, data_admin=dataAdmin, 
                               article_count=article_count, postingan_count=postingan_count, 
                               mahasiswa_count=mahasiswa_count, pelaporan_count=pelaporan_count, 
                               summary_pelaporan_byMonth=summary_pelaporan_byMonth, 
                               summary_pelaporan_byYear=summary_pelaporan_byYear)
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
        flash('Anda Belum Login', 'error')
        return redirect(url_for("loginAdmin"))
    
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
    token_key = request.cookies.get('token')
    if not token_key:
        return redirect(url_for('loginAdmin'))
    try:
        payload = jwt.decode(token_key, SECRET_KEY, algorithms=['HS256'])
        if not payload:
            flash("something wrong", "error")
            return redirect(url_for('loginAdmin'))
    except jwt.ExpiredSignatureError:
        flash("Token Expired", "error")
        return redirect(url_for('loginAdmin'))
    except jwt.InvalidTokenError:
        flash("Invalid Token", "error")
        return redirect(url_for('loginAdmin'))
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
        flash('Anda Belum Login', 'error')
        return redirect(url_for("loginAdmin" ))
  
@app.route('/updateLaporan/<no_resi>', methods=['POST'])
def updatestatus(no_resi):
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('loginAdmin'))
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        if not payload:
            return redirect(url_for('loginAdmin'))
    except jwt.ExpiredSignatureError:
        return redirect(url_for('loginAdmin'))
    except jwt.InvalidTokenError:
        return redirect(url_for('loginAdmin'))
    status_receive = request.form.get('new_status')
    db.pelaporan.update_one({'no_resi': no_resi}, {'$set': {'status': status_receive}})
    flash('Status Laporan berhasil diubah!', 'success')
    return redirect(url_for('detailLaporan'))
     
        
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
        flash('Anda Belum Login', 'error')
        return redirect(url_for("loginAdmin" ))
    
@app.route('/deletePostbyAdmin', methods=['POST'])
def deletePostbyAdmin():
    token_receive = request.cookies.get('token')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        if not payload:
            return redirect(url_for('loginAdmin'))
    except jwt.ExpiredSignatureError:
        return redirect(url_for('loginAdmin'))
    except jwt.InvalidTokenError:
        return redirect(url_for('loginAdmin'))
    post_id = request.form.get('post_id_give')
    db.postingan.delete_one({'_id': ObjectId(post_id)})
    flash('Postingan berhasil dihapus!', 'success')
    return redirect(url_for('forumControl'))   
    
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
                "role": "mahasiswa",
                "fotoProfile": "foto_profil/Default-profile-image.png"
            }
            # duplicate username check
            if db.mahasiswa.find_one({"nim": mahasiswa_nim}):
                flash("NIM sudah terdaftar!")
                return redirect(url_for("userControl"))
            else:         
                db.mahasiswa.insert_one(data)      
            return redirect(url_for('userControl'))
    
        token_receive = request.cookies.get('token')
        try:
            payload = jwt.decode(token_receive, SECRET_KEY, algorithms=["HS256"])
            if payload.get('role') != 'admin' and payload.get('role') != 'superAdmin':
                return redirect('/')
            user_info = db.admin.find_one({"username": payload["id"],
                                           "role": payload["role"]
                                           })
            dataUser = list(db.mahasiswa.find())   
            return render_template('admin/adminUserControl.html',data=user_info, data_user = dataUser )     
        except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
            flash('Anda Belum Login', 'error')
            return redirect(url_for("loginAdmin" ))

@app.route('/updateMahasiswa', methods=['POST'])
def updateUser():
    token_receive = request.cookies.get('token')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        if not payload:
            return redirect(url_for('loginAdmin'))
    except jwt.ExpiredSignatureError:
        return redirect(url_for('loginAdmin'))
    except jwt.InvalidTokenError:
        return redirect(url_for('loginAdmin'))

    mahasiswa_nim = request.form.get('nim')
    new_status = request.form.get('status_give')

    # Check the current status before updating
    current_info = db.mahasiswa.find_one({'nim': mahasiswa_nim})
    if current_info and 'status' in current_info and current_info['status'] != new_status:
        if new_status == 'hide':
            # Pindahkan user ke db.pinalty
            posts_to_move = list(db.postingan.find({'nim': mahasiswa_nim}))
            if posts_to_move:
                db.pinalty.insert_many(posts_to_move)
                db.postingan.delete_many({'nim': mahasiswa_nim})
        elif new_status == 'show':
            # kembalikan user sessuai denga db.postingan sebelumnya
            posts_to_restore = list(db.pinalty.find({'nim': mahasiswa_nim}))
            if posts_to_restore:
                db.postingan.insert_many(posts_to_restore)
                db.pinalty.delete_many({'nim': mahasiswa_nim})

    # Update the student's information
    mahasiswa_name = request.form.get('new_name')
    mahasiswa_email = request.form.get('new_email')
    mahasiswa_prodi = request.form.get('new_prodi')
    ibu_mahasiswa = request.form.get('new_mother_name')
    data = {
        "nama": mahasiswa_name,
        "email": mahasiswa_email,
        "program_studi": mahasiswa_prodi,
        "nama_ibu": ibu_mahasiswa,
        "status": new_status
    }
    db.mahasiswa.update_one({'nim': mahasiswa_nim}, {'$set': data})
    flash('Data Mahasiswa berhasil diubah!', 'success')
    return redirect(url_for('userControl'))

@app.route('/resetMahasiswa', methods=['POST'])
def reset():
    token_receive = request.cookies.get('token')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        if not payload:
            return redirect(url_for('loginAdmin'))
    except jwt.ExpiredSignatureError:
        return redirect(url_for('loginAdmin'))
    except jwt.InvalidTokenError:
        return redirect(url_for('loginAdmin'))
    nim_receive = request.form.get('nim')
    # delete kolom password_new dari koleksi mahasiswa
    db.mahasiswa.update_one({'nim': nim_receive}, {'$unset': {'password_new': ""}})
    flash('Akun berhasil direset!', 'success')
    return redirect(url_for('userControl'))

@app.route('/adminDashboard/deleteArticle/<article_id>', methods=['POST'])
def delete_article(article_id):
    token_receive = request.cookies.get('token')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=["HS256"])
        if payload.get('role') not in ['admin', 'superAdmin']:
            return redirect('/')
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for("loginAdmin"))
    try:
        db.article.delete_one({"_id": ObjectId(article_id)})
        flash('Artikel berhasil dihapus!', 'success')
        return jsonify({"success": True})
    except Exception as e:
        flash('Gagal menghapus artikel!', 'error')
        return jsonify({"success": False, "error": str(e)})

# Admin - Edit Article
@app.route('/adminDashboard/editArticle/<article_id>', methods=['POST'])
def edit_article(article_id):
    token_receive = request.cookies.get('token')
    if not token_receive:
        return redirect(url_for('loginAdmin'))
    try:
        title_receive = request.form["judulArtikel_give"]
        isi_receive = request.form["isiArtikel_give"]
        date_receive = request.form["dateArtikel_give"]
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
                # hapus gambar lama
                old_article = db.article.find_one({"_id": ObjectId(article_id)})
                old_image_path = old_article.get("gambar")
                if old_image_path:
                    old_image_path = os.path.join(app.root_path, 'static/', old_image_path)
                    if os.path.exists(old_image_path):
                        os.remove(old_image_path) 
                #Tambah gambar baru 
                gambar_receive = request.files["gambarArtikel_give"]
                extensiongambar = gambar_receive.filename.split('.')[-1]
                save_dir = os.path.join(app.root_path, 'static/adminAsset/articleImage/')
                os.makedirs(save_dir, exist_ok=True)   
                filename = f'image{date_time}.{extensiongambar}'
                save_gambar = os.path.join('adminAsset/articleImage/', filename)   
                gambar_receive.save(os.path.join(save_dir, filename))
                update_data['gambar'] = save_gambar

        db.article.update_one({"_id": ObjectId(article_id)}, {"$set": update_data})
        flash('Artikel berhasil diubah!', 'success')
        return redirect(url_for('artikelControl'))
    except Exception as e:
        flash('Gagal mengubah artikel!', 'error')
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
        os.makedirs(save_dir, exist_ok=True)   
        filename = f'image{date_time}.{extensiongambar}'
        save_gambar = os.path.join('adminAsset/articleImage/', filename)  
        gambar_receive.save(os.path.join(save_dir, filename))
        
        thisdate = today.strftime("%Y-%m-%d")

        doc = {
            'title': title_receive,
            'gambar': save_gambar,
            'isi': isi_receive,
            'date': thisdate   
        }
        db.article.insert_one(doc)
        flash('Artikel berhasil ditambahkan!', 'success')
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
        flash('Anda Belum Login', 'error')
        return redirect(url_for("loginAdmin"))

if __name__ == '__main__': 
    app.run("0.0.0.0", port=5000, debug=True)


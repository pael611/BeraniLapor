from flask import Flask,redirect,url_for,render_template,request, jsonify

app=Flask(__name__)
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

# Admin function Here, Jangan Di-edit Push dan commit apabila Masih terjadi Eror!

@app.route('/loginPetugasSatgas', methods=['GET', 'POST'])
def loginAdmin():
    if request.method == 'POST':
        # Handle POST Request here
        return render_template('admin/loginAdmin.html')
    return render_template('admin/loginAdmin.html')

@app.route('/adminDashboard', methods=['GET', 'POST'])
def adminDashboard():
    if request.method == 'POST':
        # Handle POST Request here
        return render_template('admin/adminDashboard.html')
    return render_template('admin/adminDashboard.html')

@app.route('/adminControl', methods=['GET', 'POST'])
def adminControl():
    if request.method == 'POST':
        # Handle POST Request here
        return render_template('admin/adminControl.html')
    return render_template('admin/adminControl.html')

@app.route('/adminDashboard/detailLaporan', methods=['GET', 'POST'])
def detailLaporan():
    if request.method == 'POST':
        # Handle POST Request here
        return render_template('admin/detailLaporan.html')
    return render_template('admin/detailLaporan.html')

@app.route('/adminDashboard/forumControl', methods=['GET', 'POST'])
def forumControl():
    if request.method == 'POST':
        # Handle POST Request here
        return render_template('admin/forumControl.html')
    return render_template('admin/forumControl.html')

@app.route('/adminDashboard/userControl', methods=['GET', 'POST'])
def userControl():
    if request.method == 'POST':
        # Handle POST Request here
        return render_template('admin/adminUserControl.html')
    return render_template('admin/adminUserControl.html')

if __name__ == '__main__':
    #DEBUG is SET to TRUE. CHANGE FOR PROD
    app.run("0.0.0.0", port=5000, debug=True)
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

@app.route("/sign_in", methods=["POST"])
def sign_in():
    username_receive = request.form['username_give']
    password_receive = request.form['password_give']
    
    return jsonify({'msg': 'Login berhasil!'})

@app.route("/update_password", methods=["POST"])
def update_password():
    username_receive = request.form['username_give']
    new_pw_receive = request.form['new_password_give']
    
    return jsonify({'msg': 'Password Anda berhasil diubah!'})

@app.route("/sign_up", methods=["POST"])
def sign_up():
    namaLengkap_receive = request.form['namaLengkap_give']
    username_register_receive = request.form['username_register_give']
    email_receive = request.form['email_give']
    pw_register_receive = request.form['pw_register_give']
    
    return jsonify({'msg': 'Akun baru berhasil dibuat!'})

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
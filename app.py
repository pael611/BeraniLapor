from flask import Flask,redirect,url_for,render_template,request

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

@app.route('/forumBase', methods=['GET', 'POST'])
def forum():
     
    return render_template('forum.html')

# Admin function Here, Jangan Di-edit Push dan commit apabila Masih terjadi Eror!
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
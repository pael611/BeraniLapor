from flask import Flask,redirect,url_for,render_template,request

app=Flask(__name__)
@app.route('/',methods=['GET','POST'])
def home():
    if request.method=='POST':
        # Handle POST Request here
        return render_template('index.html')
    return render_template('index.html')

@app.route('/loginUser', methods=['GET', 'POST'])
def loginUser():
    if request.method == 'POST':
        # Handle POST Request here
        return render_template('login.html')
    return render_template('login.html')
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
if __name__ == '__main__':
    #DEBUG is SET to TRUE. CHANGE FOR PROD
    app.run(port=5000,debug=True)
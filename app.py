from flask import Flask,render_template 




#Create The App
app = Flask(__name__)



#Create The Main Page
@app.route('/')
def index():
    return render_template('index.html')
from flask import Flask,render_template,redirect,url_for,request,flash
from flask_wtf import FlaskForm
from wtforms import StringField,SubmitField,PasswordField,BooleanField,ValidationError
from wtforms.validators import DataRequired,EqualTo,Length
from wtforms.widgets import TextArea
from flask_sqlalchemy import SQLAlchemy
import os
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import UserMixin,login_user,LoginManager,login_required,logout_user,current_user



#Create The App
app = Flask(__name__)
#Create A CSRF Token
app.config["SECRET_KEY"] = "mysecretkey"
#Add The Database
basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "users.db")
#Initialize The Database
db = SQLAlchemy(app)
#Add Migrate
migrate = Migrate(app, db)
#Add Some Login Things
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view='login'
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


#Create Database Table
class Users(db.Model,UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(80),nullable=False)
    username = db.Column(db.String(80),nullable=False,unique=True)
    email = db.Column(db.String(80),nullable=False,unique=True)
    secret_word = db.Column(db.String(20),nullable=False)
    password_hash = db.Column(db.String(128))
    #Setting Up Hash Passwords
    @property
    def password(self):
        raise AttributeError("password is unreadable")
    @password.setter
    def password(self,password):
        self.password_hash = generate_password_hash(password)
    def verify_password(self,password):
        return check_password_hash(self.password_hash,password)

    #Create A String
    def __repr__(self):
        return '<Name %r>' % self.name


#Create A Login Form
class LoginForm(FlaskForm):
    username = StringField("Username",validators=[DataRequired()])
    password_hash = PasswordField("Password",validators=[DataRequired()])
    submit = SubmitField("Login")


#Create A Register Form
class RegisterForm(FlaskForm):
    name = StringField("Name",validators=[DataRequired()])
    username = StringField("Username",validators=[DataRequired()])
    email = StringField("Email",validators=[DataRequired()])
    secret_word = StringField("Secret Word",validators=[DataRequired()])
    password_hash = PasswordField('Password',validators=[DataRequired(),EqualTo('password_hash2',message ='Passwords Must Match')])
    password_hash2 =PasswordField('Confirm Password',validators=[DataRequired()])
    submit = SubmitField("Submit")

#Create The Main Page
@app.route('/')
def index():
    return render_template('index.html')

#Create Register Page
@app.route('/register',methods=["POST","GET"])
def register():
    name = None
    form = RegisterForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            #Hash Password
            hashed_pw = generate_password_hash(form.password_hash.data, method='pbkdf2:sha256')
            user = Users(name=form.name.data,username=form.username.data,email=form.email.data,secret_word=form.secret_word.data,password_hash=hashed_pw)
            db.session.add(user)
            db.session.commit()
        name = form.name.data
        form.name.data = ''
        form.username.data = ''
        form.email.data = ''
        form.secret_word.data = ''
        flash("You Registered Successfully")
    all_users = Users.query.order_by(Users.username)
    return render_template("register.html",form=form,name=name,all_users=all_users)

#Remove User
@app.route('/remove_user/<int:id>')
def remove_user(id):
    user_to_remove = Users.query.get_or_404(id)
    name = None
    form = RegisterForm()
    try:
        db.session.delete(user_to_remove)
        db.session.commit()
        flash("User Removed Successfully")
        all_users = Users.query.order_by(Users.username)
        return render_template('register.html',form=form,all_users=all_users,name=name)
    except:
        flash("Whoops!Something Went Wrong,Please Try Again.")
        return render_template('register.html',form=form,all_users=all_users,name=name)


#Create Dashboard Page
@app.route('/dashboard',methods=["GET","POST"])
@login_required
def dashboard():
    form = RegisterForm()
    id = current_user.id  
    name_to_edit = Users.query.get_or_404(id)
    if request.method == "POST":
        name_to_edit.name = request.form['name']
        name_to_edit.username = request.form['username']
        name_to_edit.email = request.form['email']
        name_to_edit.secret_word = request.form['secret_word']
        try:
            db.session.commit()
            flash("Editted User Successfully")
            return render_template("dashboard.html",form=form,
                name_to_edit=name_to_edit,id=id)
        except:
            flash("ERROR..Try Again!")
            return render_template("dashboard.html",form=form,
                name_to_edit=name_to_edit,id=id)

    else:
        return render_template("dashboard.html",form=form,
                name_to_edit=name_to_edit,id=id)
    return render_template('dashboard.html',form=form)




#Create Login Page
@app.route('/login',methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            #Check the hash
            if check_password_hash(user.password_hash,form.password_hash.data):
                login_user(user)
                flash("Login Successfully")
                return redirect(url_for('dashboard'))
            else:
                flash("Wrong password")
        else:
            flash("That user doesn't exist,Try again!")
    return render_template('login.html',form=form)

#Create A Logout Function
@app.route('/logout',methods=["GET","POST"])
@login_required
def logout():
    logout_user()
    flash("You have been logged out")
    return redirect(url_for('login'))

#Create Edit User Function
@app.route('/edit_user/<int:id>',methods=["POST","GET"])
def edit_user(id):
    form = RegisterForm()
    name_to_edit = Users.query.get_or_404(id)
    if request.method == "POST":
        name_to_edit.name = request.form['name']
        name_to_edit.username = request.form['username']
        name_to_edit.email = request.form['email']
        name_to_edit.secret_word = request.form['secret_word']
        try:
            db.session.commit()
            flash("User Editted Successfully")
            return render_template('edit_user.html',form=form,name_to_edit=name_to_edit,id=id)
        except:
            flash("ERROR! Looks like there was a problem.Try again!")
            return render_template('edit_user.html',form=form,name_to_edit=name_to_edit,id=id)
    else:
        return render_template('edit_user.html',form=form,name_to_edit=name_to_edit,id=id)


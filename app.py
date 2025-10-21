from flask import Flask,render_template,redirect,url_for,request,flash
from flask_wtf import FlaskForm
from wtforms import StringField,SubmitField,PasswordField,BooleanField,ValidationError,TextAreaField
from wtforms.validators import DataRequired,EqualTo,Length
from wtforms.widgets import TextArea
from flask_sqlalchemy import SQLAlchemy
import os
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import UserMixin,login_user,LoginManager,login_required,logout_user,current_user
from datetime import datetime


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


#Create Users Database Table
class Users(db.Model,UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(80),nullable=False)
    username = db.Column(db.String(80),nullable=False,unique=True)
    email = db.Column(db.String(80),nullable=False,unique=True)
    secret_word = db.Column(db.String(20),nullable=False)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Posts',backref='poster')

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


#Create Posts Database Table
class Posts(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    title =db.Column(db.String(40),nullable=False)
    content = db.Column(db.Text,nullable=False)
    date_posted = db.Column(db.DateTime,default=datetime.utcnow)
    #Create One to Many Relationship 
    poster_id = db.Column(db.Integer,db.ForeignKey('users.id'))
    likes = db.Column(db.Integer,nullable=False,default=0,server_default="0")


#Create A Login Form
class LoginForm(FlaskForm):
    username = StringField("Username",validators=[DataRequired()])
    password_hash = PasswordField("Password",validators=[DataRequired()])
    submit = SubmitField("Login")


#Create a Post Form
class PostForm(FlaskForm):
    title = StringField("Title",validators=[DataRequired()])
    author = StringField("Author")
    content = TextAreaField("Content",validators=[DataRequired()])
    submit = SubmitField("Post")

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
    most_liked_posts = Posts.query.order_by(Posts.likes.desc()).limit(5).all()
    return render_template('index.html',most_liked_posts=most_liked_posts)

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
    posts = list(user_to_remove.posts)
    name = None
    form = RegisterForm()
    try:
        for post in posts:
            db.session.delete(post)
        db.session.delete(user_to_remove)
        db.session.commit()
        flash("User Removed Successfully")
        all_users = Users.query.order_by(Users.username)
        return render_template('register.html',form=form,all_users=all_users,name=name)
    except:
        flash("Whoops!Something Went Wrong,Please Try Again.")
        return render_template('register.html',form=form,all_users=all_users,name=name)
    redirect(url_for("dashboard"))

#Create Dashboard Page
@app.route('/dashboard',methods=["GET","POST"])
@login_required
def dashboard():
    form = RegisterForm()
    all_users = Users.query.order_by(Users.username)
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
                name_to_edit=name_to_edit,id=id,all_users=all_users)
        except:
            flash("ERROR..Try Again!")
            return render_template("dashboard.html",form=form,
                name_to_edit=name_to_edit,id=id,all_users=all_users)

    else:
        return render_template("dashboard.html",form=form,
                name_to_edit=name_to_edit,id=id,all_users=all_users)
    return render_template('dashboard.html',form=form,all_users=all_users)




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
    flash("Logged out! See  you again")
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

#Create add_post Route
@app.route('/add_post',methods=["GET","POST"])
@login_required
def add_post():
    form = PostForm()
    if form.validate_on_submit():
        poster = current_user.id 
        post = Posts(title=form.title.data,content=form.content.data,poster_id=poster,likes=0)
        #Clear The Form
        form.title.data = ''
        form.content.data = ''
        #Add To Database
        db.session.add(post)
        db.session.commit()
        flash("Blog Uploaded Successfully")
    return render_template("add_post.html",form=form)

#Create Route For Posts
@app.route('/posts')
def posts():
    posts = Posts.query.order_by(Posts.date_posted)
    return render_template("posts.html",posts=posts)


#Create delete_post function
@app.route('/delete_post/<int:id>')
def delete_post(id):
    post_to_delete = Posts.query.get_or_404(id)
    id = current_user.id
    if id == post_to_delete.poster_id:
        try:
            db.session.delete(post_to_delete)
            db.session.commit()
            flash("Post Deleted Successfully ")
            posts = Posts.query.order_by(Posts.date_posted)
            return render_template('posts.html',posts=posts)
        except:
            flash("Something wen't wrong! Please try again")
            posts = Posts.query.order_by(Posts.date_posted)
            return render_template('posts.html',posts=posts)
    else:
        flash("You aren't authorized to delete that post")
        posts = Posts.query.order_by(Posts.date_posted)
        return render_template("posts.html",posts=posts)

#Create Edit Post Function
@app.route('/edit_post/<int:id>',methods=["POST","GET"])
def edit_post(id):
    form = PostForm()
    post_to_edit = Posts.query.get_or_404(id) 
    if form.validate_on_submit():
        post_to_edit.title = form.title.data
        post_to_edit.content = form.content.data
        db.session.add(post_to_edit)
        db.session.commit()
        flash("Successfully Editted The Post")
        return redirect(url_for('posts',id=post_to_edit.id))
    if current_user.id == post_to_edit.poster_id:
        form.title.data = post_to_edit.title
        form.content.data = post_to_edit.content
        return render_template('edit_post.html',form=form)
    else:
        flash("You aren't authorized to edit that post")
        posts = Posts.query.order_by(Posts.date_posted)
        return render_template('posts.html',posts=posts)

#Create a Route for viewing post
@app.route('/post/<int:id>')
def post(id):
    post_to_view = Posts.query.get_or_404(id)
    return render_template('post.html',post_to_view=post_to_view)

#Create "Like-A-Post" function
@app.route('/like_post/<int:id>')
@login_required
def like_post(id):
    post_to_like = Posts.query.get_or_404(id)
    try:
        post_to_like.likes += 1
        db.session.commit()
        flash("Post Liked Successfully")
        return redirect(url_for('posts'))
    except:
        flash("Something went wrong! Please try again...")
        return redirect(url_for('posts'))


#Create my_posts route
@app.route('/my_posts')
@login_required
def my_posts():
    my_posts = Posts.query.filter_by(poster_id=current_user.id).order_by(Posts.date_posted.desc()).all()
    return render_template('my_posts.html',my_posts=my_posts)

#Create Statistics function
@app.route('/statistics/<int:id>')
@login_required
def statistics(id):
    user_statistics = Users.query.get_or_404(id)
    total_likes = sum(post.likes for post in user_statistics.posts)
    total_posts = len(user_statistics.posts)
    return render_template('statistics.html',total_likes=total_likes,total_posts=total_posts,user=user_statistics)


#Adding Error Handler 404
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

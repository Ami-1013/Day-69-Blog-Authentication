from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from requests import request
from sqlalchemy import ForeignKey
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from functools import wraps
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Using Gravatar for user avatar
gravatar = Gravatar(app)
# The avatar does'nt change after site is relaunch, it is permanently is attach to profile.


# user loader
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)




# Relationship declarative base
Base = declarative_base()

##CONFIGURE TABLES

class User(UserMixin, db.Model, Base):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    
    # creating one - many bidirectional relation with Comment table
    comments = relationship("Comment", back_populates="comment_author")

class BlogPost(db.Model, Base):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    
    #  'user' is a table name
    author_id = db.Column(db.Integer, ForeignKey("user.id"))
    author = relationship("User", back_populates="posts")
    # "author" attr store "User" table "objects in list". 

    # creating one-many bidirectional relationship with Comment table
    comments = relationship("Comment", back_populates="parent_post")

# Here "User" table can use "BlogPost" properties by 'posts' attribute, like - ___.posts.subtitle
# Similarly for "BlogPost" is by 'author' attribute
# Attribute "posts" in User and "author" in BlogPost table keep collection of data of other table. Depending how relation is define. 

# The relation item "objects are stored in a list" in defined attribute. Hence all objects of "Comment" table are stored 
# in "comment" attribute of "BlogPost" and "User" table depending on relation and "ForeignKey".
 
# In "Foreignkey" there is __.id because id is the primary key of other table.

class Comment(db.Model, Base):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    # A StingField can hold up to 250 char and Text can hold up to 30,000 chars.
    
    # relation with User table
    author_id = db.Column(db.Integer, ForeignKey("user.id"))
    comment_author = relationship("User", back_populates="comments")
    
    # relation with BlogPost table
    post_id = db.Column(db.Integer, ForeignKey("blog_posts.id"))
    # This "comment" is of BlogPost table as specified in relation.
    parent_post = relationship("BlogPost", back_populates="comments")
 
# You can  use more than 1 "ForeignKey" in a Table.
# db.create_all()


# Decorating the admin_only f

def admin_only(f):
    @wraps(f)
    # *args and **kwargs because route will required some args or kwargs to work like id = 2
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        
        return f(*args, **kwargs)      

    return decorated_function    
# This decorator "admin_only" should be below route decorator

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    print(current_user.is_authenticated)
    return render_template("index.html", all_posts=posts, current_user = current_user)


@app.route('/register', methods=["GET", "POST"])
def register():

    form = RegisterForm()
    if form.validate_on_submit():

        # if user account already exist.
        if User.query.filter_by(email=form.email.data).first():
            flash("The Email already exit. Please login to continue.")
            return redirect(url_for("login"))

        # Filling a new entry in user table.

        hash_and_salted_password = generate_password_hash(password=form.password.data, method='pbkdf2:sha256', salt_length=8)
       
        new_user = User(
        email = form.email.data,
        password = hash_and_salted_password,
        name = form.name.data)

        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)

        return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=form, current_user = current_user)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        # The below User.query. return a boolean 
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("The given email does'nt exist.")
            return redirect(url_for("login"))
        
        elif not check_password_hash(pwhash=user.password, password=password): 
            flash("The password is incorrect.")
            return redirect(url_for("login"))
        
        else:          
            login_user(user) 
            return redirect(url_for("get_all_posts"))

    return render_template("login.html", form=form, current_user = current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts', current_user = current_user))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):

    requested_post = BlogPost.query.get(post_id)
    # Creating comment form
    comment_form = CommentForm()
    if comment_form.validate_on_submit():

        # checking user is authenticated , if not then redirecting it to login page.
        if not current_user.is_authenticated:
            flash("Please login to comment.")
            return redirect(url_for("login"))


        comment = comment_form.comment.data
        # **** Below line has a deep meaning, understand it ****
        # comment_author and current_user are of "User" table & parent_post and requested_post are of "BlogPost" table.
        # So by matching objects it automatically give value to "author_id" and "post_id"
        new_comment = Comment(text=comment, comment_author=current_user, parent_post=requested_post)
        db.session.add(new_comment)
        db.session.commit()
    # Remember all Comments of a blog is present in its "comment" attribute as "object in a list".
    return render_template("post.html", post=requested_post, comment_form = comment_form, current_user = current_user)


@app.route("/about")
def about():
    return render_template("about.html", current_user = current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user = current_user)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user = current_user)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, current_user = current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts', current_user = current_user))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)


# You can create more then one table in database. Here __tablename__ plays a imp role.

# "request.form.get()" is used when html form is used and "form.___.data" is used when wtfform/quick is used

# abort() f give http errors with a clean and blank page.

# Why in route "make-post" author = current_user not current_user.name ?
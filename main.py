import flask
import sqlalchemy
from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from flask_gravatar import Gravatar
from sqlalchemy.ext.declarative import declarative_base
from functools import wraps
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm


def admin_permissions(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        if current_user.id != 1:
            abort(403, description='You have no admin rights')
        return func(*args, **kwargs)

    return decorated


Base = declarative_base()
app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blogs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES

class BlogPost(db.Model, Base):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # refers to tablename 'users' and id attribute
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    # refers to class name User and its attribute children
    # Create reference to the User object, the "posts" refers to the posts property in the User class.

    author = relationship('User', back_populates='posts')
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    comments = relationship('Comments', back_populates='post')


class User(db.Model, UserMixin, Base):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(32), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    # refers to class name BlogPost and its attribute parent
    posts = relationship('BlogPost', back_populates='author')
    comments = relationship('Comments', back_populates='author')

    if id == 1:
        admin = True
    else:
        admin = False


class Comments(db.Model, Base):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship('User', back_populates='comments')
    body = db.Column(db.Text, nullable=False)

    post = relationship('BlogPost', back_populates='comments')
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))


db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


@app.route('/register', methods=["GET", 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        if User.query.filter_by(email=email).first():
            flask.flash('You have been registered. Log in instead.')
            return redirect(url_for('login'))

        hashed_password = generate_password_hash(
            password=form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )

        login_field = form.login.data
        password = hashed_password
        new_user = User(
            email=email,
            name=login_field,
            password=password
        )
        db.session.add(new_user)
        db.session.commit()

        login_user(user=new_user)
        return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        alt_user = User.query.filter_by(email=email).first()
        print('Form validated')
        if alt_user:
            password = form.password.data
            print('User exists')
            checked = check_password_hash(pwhash=alt_user.password, password=password)
            if checked:
                login_user(user=alt_user)
                return redirect(url_for('get_all_posts'))
            else:
                flask.flash('Incorrect password')
                return redirect(url_for('login'))
        else:
            flask.flash('Particular email have no account. Please register first')
            return redirect(url_for('register'))
    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    comments = requested_post.comments
    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comments(
                body=form.body.data,
                author=current_user,
                post=requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
        else:
            flask.flash('Log in first')
            return redirect(url_for('login'))
    return render_template("post.html", post=requested_post, current_user=current_user, form=form, comments=comments, gravatar=gravatar)


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)


@app.route("/new-post", methods=['GET', 'POST'])
@admin_permissions
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
    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
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

    return render_template("make-post.html", form=edit_form, current_user=current_user)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)

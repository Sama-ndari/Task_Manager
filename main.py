from flask import Flask, render_template, redirect, abort, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
from forms import *
from flask_bootstrap import Bootstrap
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = "posooo"
# app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
# app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
db = SQLAlchemy(app)
Bootstrap(app)


login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)

    return decorated_function


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    lists = db.relationship('List', back_populates="user")
    tasks = db.relationship("Task", back_populates="user")


class List(db.Model):
    __tablename__ = "lists"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    user = db.relationship("User", back_populates="lists")
    tasks = db.relationship('Task', back_populates="list")


class Task(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    completed = db.Column(db.Boolean, default=False)

    list_id = db.Column(db.Integer, db.ForeignKey('lists.id'), nullable=False)
    list = db.relationship("List", back_populates="tasks")

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    user = db.relationship("User", back_populates="tasks")


# with app.app_context():
#     db.create_all()


@app.route('/')
def index():
    return render_template("index.html")


@login_required
@app.route('/settings')
def settings():
    return render_template("settings.html")


# ********************    LISTS    *********************

@login_required
@app.route('/create-list', methods=['GET', 'POST'])
def get_all_lists():
    form = ListForm()
    if form.validate_on_submit():
        new_list = List(name=form.name.data,
                        user=current_user)
        db.session.add(new_list)
        db.session.commit()
        return redirect(url_for('show_list', id_list=new_list.id))
    lists = current_user.lists
    return render_template("lists.html", form=form, lists=lists, edit=False)


@login_required
@app.route('/delete-list/<int:id_list>')
def delete_list(id_list):
    list_to_delete = List.query.get(id_list)
    if list_to_delete.user == current_user or current_user.id == 1:
        for task in list_to_delete.tasks:
            db.session.delete(task)
            db.session.commit()
        db.session.delete(list_to_delete)
        db.session.commit()
    return redirect(url_for('get_all_lists'))


@login_required
@app.route('/edit-list/<int:id_list>', methods=['GET', 'POST'])
def edit_list(id_list):
    the_list = List.query.get(id_list)
    if the_list.user != current_user and current_user.id != 1:
        return redirect(url_for('get_all_lists'))
    form = ListForm(name=the_list.name)
    if form.validate_on_submit():
        the_list.name = form.name.data
        db.session.commit()
        return redirect(url_for('get_all_lists'))
    lists = current_user.lists
    return render_template("lists.html", form=form, lists=lists, edit=True, the_list=the_list)


# ********************    TASK    *********************


@login_required
@app.route('/create-task/<int:id_list>', methods=['GET', 'POST'])
def show_list(id_list):
    form = TaskForm()
    the_list = List.query.get(id_list)
    if form.validate_on_submit():
        task = Task(title=form.title.data,
                    description=form.description.data,
                    list=the_list,
                    user=current_user)
        db.session.add(task)
        db.session.commit()
        return redirect(url_for('show_list', id_list=the_list.id))
    return render_template("list.html", form=form, list_=the_list, edit=False)


@login_required
@app.route('/complete/<int:id_task>')
def complete_task(id_task):
    task = Task.query.get(id_task)
    if task.user == current_user or current_user.id == 1:
        task.completed = True
        db.session.commit()
    return redirect(url_for('show_list', id_list=task.list_id))


@login_required
@app.route('/delete-task/<int:id_task>')
def delete_task(id_task):
    task = Task.query.get(id_task)
    list_id = task.list_id
    if task.user == current_user or current_user.id == 1:
        db.session.delete(task)
        db.session.commit()
    return redirect(url_for('show_list', id_list=list_id))


@login_required
@app.route('/edit-task/<int:id_task>', methods=['GET', 'POST'])
def edit_task(id_task):
    task = Task.query.get(id_task)
    the_list = task.list
    if task.user != current_user and current_user.id != 1:
        return redirect(url_for('show_list', id_list=task.user_id))
    form = TaskForm(title=task.title,
                    description=task.description
                    )
    if form.validate_on_submit():
        task.title = form.title.data
        task.description = form.description.data
        db.session.commit()
        return redirect(url_for('show_list', id_list=the_list.id))
    return render_template("list.html", form=form, list_=the_list, edit=True, task=task)


# ********************    USER    *********************


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("You've already signed up with that email,login instead.")
            return redirect(url_for('login'))
        if User.query.filter_by(name=form.name.data).first():
            flash('Name unavailable,already taken.')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )

        user = User(
            name=form.name.data,
            email=form.email.data,
            password=hashed_password
        )
        db.session.add(user)
        db.session.commit()
        # Log in and authenticate user after adding details to database.
        login_user(user)
        return redirect('/')

    return render_template('register.html', form=form, edit=False)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        remember = form.remember.data

        user = User.query.filter_by(email=email).first()
        # Email doesn't exist
        if not user:
            flash("That email does not exist, please try again.", category='error')
        # Password incorrect
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.', category='error')
        else:
            login_user(user, remember=remember)
            return redirect('/')
    return render_template('login.html', form=form)


@app.route("/edit-user/<int:user_id>", methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if user_id == 1:
        return redirect(url_for('index'))
    if current_user.id != 1 and current_user.id != user_id:
        return redirect(url_for('index'))
    user_to_edit = User.query.get(user_id)
    form = RegisterForm(
        email=user_to_edit.email,
        name=user_to_edit.name
    )
    if form.validate_on_submit():
        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        user_to_edit.name = form.name.data
        user_to_edit.password = hash_and_salted_password
        user_to_edit.email = form.email.data
        db.session.commit()
        logout_user()  # you first log out the actual user
        # Log in and authenticate user after adding details to database.
        login_user(user_to_edit)
        return redirect(url_for('index'))
    return render_template("register.html", form=form, edit=True)


@app.route("/delete-user/<int:user_id>")
@login_required
def delete_user(user_id):
    if user_id == 1:
        return redirect(url_for('index'))
    if user_id == current_user.id or current_user.id == 1:
        user_to_delete = User.query.get(user_id)
        # deleting all the tasks of the user to delete
        for task in Task.query.filter_by(user=user_to_delete).all():
            db.session.delete(task)
            db.session.commit()
        # deleting all the lists of the user
        for list_ in List.query.filter_by(user=user_to_delete).all():
            db.session.delete(list_)
            db.session.commit()
        db.session.delete(user_to_delete)
        db.session.commit()
    return redirect(url_for('index'))


@app.route("/secure")
@admin_only  # only Admin will ceo
def security():
    users = User.query.all()
    return render_template('ceo.html', users=users)


@app.route("/reset-user/<int:user_id>")
@admin_only  # only Admin will reset
def reset_user(user_id):
    if user_id == 1:
        return redirect(url_for('index'))
    user = User.query.get(user_id)
    hash_and_salted_password = generate_password_hash(
        '0000',
        method='pbkdf2:sha256',
        salt_length=8
    )
    user.password = hash_and_salted_password
    db.session.commit()
    return redirect(url_for('index'))


@login_required
@app.route('/logout')
def logout():
    logout_user()
    return redirect('/')


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


if __name__ == '__main__':
    app.run(debug=True)

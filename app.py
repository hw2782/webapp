from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
import bcrypt
from flask_wtf.file import FileField, FileAllowed
from wtforms import TextAreaField, SubmitField
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data["_id"])
        self.username = user_data["username"]

    def __repr__(self):
        return f"<User {self.username}>"

class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    security_question = StringField("Security Question", validators=[DataRequired()])
    security_answer = StringField("Security Answer", validators=[DataRequired()])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class ForgotPasswordForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    submit = SubmitField("Submit")
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
@login_manager.user_loader
def load_user(user_id):
    user_data = db.users.find_one({"_id": ObjectId(user_id)})
    if user_data:
        return User(user_data)
    return None
class CreatePostForm(FlaskForm):
    subject = StringField("Subject", validators=[DataRequired()])
    content = TextAreaField("Content", validators=[DataRequired()])
    image = FileField("Upload Image", validators=[FileAllowed(['jpg', 'png', 'jpeg', 'gif'])])
    submit = SubmitField("Create Post")

class SearchForm(FlaskForm):
    search_query = StringField("Search", validators=[DataRequired()])
    submit = SubmitField("Search")
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = bcrypt.hashpw(form.password.data.encode("utf-8"), bcrypt.gensalt())
        security_question = form.security_question.data
        security_answer = form.security_answer.data.lower()

        # Check if the username is already taken
        existing_user = db.users.find_one({"username": username})
        if existing_user is None:
            db.users.insert_one({"username": username, "password": password, "security_question": security_question, "security_answer": security_answer})
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))
        else:
            flash("Username already taken. Please choose another.", "error")

    return render_template('register.html', form=form)

@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        existing_user = db.users.find_one({"username": username})
        if existing_user and bcrypt.checkpw(password.encode("utf-8"), existing_user["password"]):
            flash("Login successful.", "success")
            # Implement your logic here for successful login
            return redirect(url_for("home")) # Replace "home" with the desired route
        else:
            flash("Invalid username or password.", "error")

    return render_template('login.html', form=form)

@app.route('/forgot_password', methods=["GET", "POST"])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        username = form.username.data

        existing_user = db.users.find_one({"username": username})
        if existing_user:
            flash(f"Security Question: {existing_user['security_question']}", "info")
            # Implement your logic here for password recovery based on the security question and answer
        else:
            flash("Username not found.", "error")

    return render_template('forgot_password.html', form=form)
@app.route('/create_post', methods=["GET", "POST"])
@login_required
def create_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        subject = form.subject.data
        content = form.content.data
        image = form.image.data
        user_id = current_user.get_id()

        post = {
            "subject": subject,
            "content": content,
            "image": image.read(),
            "author": ObjectId(user_id),
            "created_at": datetime.datetime.utcnow()
        }
        db.posts.insert_one(post)
        flash("Post created successfully.", "success")
        return redirect(url_for("home"))

    return render_template('create_post.html', form=form)

@app.route('/search', methods=["GET", "POST"])
def search():
    form = SearchForm()
    search_results = []
    if form.validate_on_submit():
        search_query = form.search_query.data
        search_results = db.posts.find({
            "$or": [
                {"subject": {"$regex": search_query, "$options": 'i'}},
                {"content": {"$regex": search_query, "$options": 'i'}}
            ]
        }).sort("created_at", -1)

    return render_template('search.html', form=form, search_results=search_results)

if __name__ == "__main__":
    app.run()
    

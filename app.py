from flask import Flask, render_template, url_for, redirect 
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, current_user, login_user
from flask import current_app
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Email 
from flask_bcrypt import Bcrypt  
from wtforms import SelectField
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta, date 
from operator import or_
app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecret22'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
app.app_context().push()
bcrypt = Bcrypt(app)
scheduler = BackgroundScheduler(daemon=True)
scheduler.start()

class User(db.Model, UserMixin):
    """
    User class representing a registered user.

    Attributes:
    - id (int): The unique identifier for the user.
    - username (str): The username of the user.
    - email (str): The email address of the user.
    - password (str): The hashed password of the user.
    """

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False) 
    password = db.Column(db.String(256), nullable=False)

    def __init__(self, username, email, password):
        """
        Initialize a User instance.

        Args:
        - username (str): The username of the user.
        - email (str): The email address of the user.
        - password (str): The plaintext password of the user.

        Note:
        The password is hashed using bcrypt before storing. 
        """
        self.username = username
        self.email = email
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        """
        Check if the provided password matches the user's stored hashed password.

    

        Returns: True if the password matches, False otherwise.
        """
        return bcrypt.check_password_hash(self.password, password)

    def __repr__(self):
        """
        Return a string representation of the User instance.
        """
        return f"<User {self.username}>"

class Habit(db.Model):
    """
    Habit class representing a user's habit.

    Attributes:
    - id (int): The unique identifier for the habit.
    - user_id (int): The foreign key referencing the user who owns the habit.
    - task (str): The description of the habit.
    - periodicity (str): The frequency of the habit (e.g., daily, weekly).
    - last_completed (datetime.date): The date when the habit was last completed.
    - current_streak (int): The current streak of completing the habit.
    - status (str): The status of the habit (e.g., pending, completed).
    - last_scheduled_check (datetime.datetime): The last time the habit's status was checked.
    - highest_streak (int): The highest streak of completing the habit.
    - struggle_score (int): The struggle score associated with the habit.
    """

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    task = db.Column(db.String(255), nullable=False)
    periodicity = db.Column(db.String(50), nullable=False)
    last_completed = db.Column(db.Date)
    current_streak = db.Column(db.Integer, default=0) 
    status = db.Column(db.String(20), default="pending")
    user = db.relationship('User', backref='habits')
    last_scheduled_check = db.Column(db.DateTime)
    highest_streak = db.Column(db.Integer, default=1)
    struggle_score = db.Column(db.Integer, default=1)

    def is_pending(self):
        """
        Check if the habit is pending based on its periodicity and completion history.

        Returns: True if the habit is pending, False otherwise.
        """
        now = datetime.now()

        if self.periodicity == "minutely":
            if self.last_completed:
                last_completed_datetime = datetime.combine(self.last_completed, datetime.min.time())
                return (now - last_completed_datetime).seconds >= 60
            return True  # If last_completed is None, it's pending
        else:
            today = date.today()
            if self.last_completed is None:
                return True  # If habit was never completed, it's pending
            if self.periodicity == "daily":
                return (today - self.last_completed).days >= 1
            elif self.periodicity == "weekly":
                return (today - self.last_completed).days >= 7
            elif self.periodicity == "monthly":
                return (today - self.last_completed).days >= 30

        return False

def update_habit_statuses():
    """
    Update the statuses and streaks of habits based on their periodicity and completion history.
    """
    now = datetime.now()
    app.app_context().push()  # Push the application context for database operations
    for habit in Habit.query.all():
        if habit.periodicity == "minutely":
            interval = timedelta(minutes=1)
        elif habit.periodicity == "daily":
            interval = timedelta(days=1)
        elif habit.periodicity == "weekly":
            interval = timedelta(weeks=1)
        elif habit.periodicity == "monthly":
            interval = timedelta(days=30)
        else:
            continue

        if habit.last_completed:
            last_completed_datetime = datetime.combine(habit.last_completed, datetime.min.time())
            if (now - last_completed_datetime) >= interval:
                if habit.status == "checked":
                    habit.status = "pending"
                    habit.current_streak += 1 - 1
                else:
                    habit.current_streak = 0 
                habit.last_scheduled_check = now
        db.session.commit()
  

scheduler.add_job(update_habit_statuses, 'interval', minutes=1)# Schedule the update_habit_statuses() function to run every minute

# This function is used by the Flask-Login extension to load a user
# based on the user_id stored in the session
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    
class RegistrationForm(FlaskForm):
    """
    Form class for user registration.

    Attributes:
    - username (StringField): The username field.
    - email (StringField): The email field.
    - password (PasswordField): The password field.
    - submit (SubmitField): The submit button.
    """

    username = StringField(
        validators=[InputRequired(), Length(min=2, max=20)],
        render_kw={"placeholder": "Username"}
    )
    email = StringField(
        validators=[InputRequired(), Email(message="Invalid email"), Length(max=120)],
        render_kw={"placeholder": "Email"}
    )
    password = PasswordField(
        validators=[InputRequired(), Length(min=5, max=30)],
        render_kw={"placeholder": "Password"}
    )
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    """
    Form class for user login.

    Attributes:
    - username (StringField): The username field.
    - password (PasswordField): The password field.
    - submit (SubmitField): The submit button.
    """

    username = StringField(
        validators=[InputRequired(), Length(min=2, max=20)],
        render_kw={"placeholder": "Username"}
    )
    password = PasswordField(
        validators=[InputRequired(), Length(min=5, max=30)],
        render_kw={"placeholder": "Password"}
    )
    submit = SubmitField("Login")

class DashboardForm(FlaskForm):
    """
    Form class for adding habits to the user's dashboard.

    Attributes:
    - habit_name (StringField): The habit name field.
    - periodicity (SelectField): The periodicity field.
    - submit (SubmitField): The submit button.
    """

    habit_name = StringField(
        validators=[InputRequired()],
        render_kw={"placeholder": "Habit Name"}
    )
    periodicity = SelectField(
        "Periodicity",
        choices=[
            ("minutely", "Minutely for testing"),
            ("daily", "Daily"),
            ("weekly", "Weekly"),
            ("monthly", "Monthly"),
        ],
        validators=[InputRequired()],
    )
    submit = SubmitField("Add Habit")

# route to the home page 
@app.route('/')
def index():
    return render_template('home.html')


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    

    """
    Render the user's dashboard page.

    If the request method is POST, handle form submission and add a new habit to the database.
    If the user is authenticated, render the dashboard page with the user's pending and checked habits.
    If the user is not authenticated, redirect to the login page.

    Returns:
    str: The rendered HTML content of the dashboard page or a redirect response.
    """
      
    form = DashboardForm()
    
    if form.validate_on_submit():
        habit_name = form.habit_name.data
        periodicity = form.periodicity.data
        
        new_habit = Habit(
            user_id=current_user.id,
            task=habit_name,
            periodicity=periodicity,
            status="pending"  # Set the initial status as pending
        )
        
        db.session.add(new_habit)
        db.session.commit()
        
        return redirect(url_for('dashboard'))
    
    if current_user.is_authenticated:
        user = current_user
        
        pending_habits = Habit.query.filter_by(user_id=user.id, status='pending').all()
        checked_habits = Habit.query.filter_by(user_id=user.id, status='checked').all()

        
        return render_template(
            'dashboard.html',
            form=form,
            pending_habits=pending_habits,
            checked_habits=checked_habits
        )
    else:
        return redirect(url_for('login'))


# Route for marking a habit as completed
@app.route('/complete_habit/<int:habit_id>', methods=['POST'])
def complete_habit(habit_id):
    habit = Habit.query.get_or_404(habit_id) # Get the habit by its ID
    
    if current_user.id == habit.user_id:
        # Update streak based on periodicity
        if habit.is_pending():
            habit.current_streak += 1 
            if habit.current_streak > habit.highest_streak:
                habit.highest_streak = habit.current_streak
        else:
            habit.current_streak = 0  # Reset streak if habit wasn't completed in time

        # Update habit completion status and timestamp
        habit.status = "checked"
        habit.last_completed = datetime.now()
        
        db.session.commit()
    
    return redirect(url_for('dashboard'))


# Route for deleting a habit
@app.route('/delete_habit/<int:habit_id>', methods=['POST'])
def delete_habit(habit_id):
    habit = Habit.query.get_or_404(habit_id)
    
    if current_user.id == habit.user_id:
        db.session.delete(habit)
        db.session.commit()
    
    return redirect(url_for('dashboard'))

# Route for displaying habits the user struggled with
@app.route('/struggle_habits', methods=['GET'])
def struggle_habits():
    if current_user.is_authenticated:
        user = current_user
        # Reset struggle scores at the beginning of each month
        today = datetime.today()
        if today.day == 1:
            Habit.query.filter_by(user_id=user.id).update({"struggle_score": 0})
            db.session.commit()
         # Query habits with the lowest highest streaks that are checked or pending
        struggle_habits = Habit.query.filter(
            (Habit.user_id == user.id) & (or_(Habit.status == 'checked', Habit.status == 'pending'))
        ).order_by(Habit.highest_streak).limit(3).all()

        return render_template('struggle_habits.html', struggle_habits=struggle_habits)
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):  
            login_user(user)  
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', form=form, error_message="Invalid credentials")
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        new_user = User(username=form.username.data, email=form.email.data, password=form.password.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)



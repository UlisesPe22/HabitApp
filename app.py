from flask import Flask, render_template, url_for, redirect 
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, current_user, login_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Email 
from flask_bcrypt import Bcrypt  
from wtforms import SelectField
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta
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
predefined_habits_data = [
    {
        'task': 'Drink a glass of water',
        'periodicity': 'daily',
        'deadline_hour': 8,
        'current_streak': 0,
        'status': 'pending',
        'highest_streak': 1,
        'struggle_score': 1,
        'added_date': current_timestamp,
        'next_pending_date': None,
    },
    {
        'task': 'Read for 30 minutes',
        'periodicity': 'daily',
        'deadline_hour': 18,
        'current_streak': 0,
        'status': 'pending',
        'highest_streak': 1,
        'struggle_score': 1,
        'added_date': current_timestamp,
        'next_pending_date': None,
    },
    {
        'task': 'Exercise for 20 minutes',
        'periodicity': 'daily',
        'deadline_hour': 15,
        'current_streak': 0,
        'status': 'pending',
        'highest_streak': 1,
        'struggle_score': 1,
        'added_date': current_timestamp,
        'next_pending_date': None,
    },
    {
        'task': 'Write a journal entry',
        'periodicity': 'weekly',
        'deadline_hour': 6,
        'current_streak': 0,
        'status': 'pending',
        'highest_streak': 1,
        'struggle_score': 1,
        'added_date': current_timestamp,
        'next_pending_date': None,
    },
    {
        'task': 'Meditate for 10 minutes',
        'periodicity': 'daily',
        'deadline_hour': 21,
        'current_streak': 0,
        'status': 'pending',
        'highest_streak': 1,
        'struggle_score': 1,
        'added_date': current_timestamp,
        'next_pending_date': None,
    },
]

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
    @classmethod
    def create_default_predefined_habits(cls, user):
        """
    Create and add default predefined habits to a user.

    Args:
    - user (User): The user for whom to create default predefined habits.

    Note:
    This method creates a set of predefined habits and associates them with the provided user.
    The predefined habit data is sourced from the `predefined_habits_data` list.
         """
        for habit_data in predefined_habits_data:
            habit = Habit(user=user, **habit_data)
            db.session.add(habit)

        db.session.commit()

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
    added_date = db.Column(db.DateTime, default=datetime.utcnow)
    next_pending_date = db.Column(db.DateTime)
    deadline_hour = db.Column(db.Integer, nullable=False)

def get_next_pending_date(periodicity, current_time, deadline_hour): 
    """
    Calculate the next pending date based on the given periodicity, current time and given deadline.

    Args:
        periodicity (str): The periodicity of the habit (e.g., "daily" or "weekly").
        current_time (datetime): The current date and time.
        deadline_hour (int): The hour at which the habit's deadline occurs.

    Returns:
        datetime: The calculated next pending date.
    """
    if periodicity == "daily":
        next_pending_date = datetime(current_time.year, current_time.month, current_time.day, deadline_hour, 0) + timedelta(days=1)
        
        return next_pending_date
    if periodicity == "weekly":
        next_pending_date = datetime(
            current_time.year, current_time.month, current_time.day, deadline_hour, 0
        ) + timedelta( weeks=1)

    return next_pending_date

    

def update_habit_statuses():
    """
    Update the statuses and streaks of habits based on their periodicity and next_pending_date.
    """
    now = datetime.now()
    with app.app_context():  # Push the application context for database operations
        for habit in Habit.query.all():

            if habit.next_pending_date is not None and habit.next_pending_date <= now:
                if habit.status == "checked":
                    print(f"Habit {habit.task} status changed to pending.")
                    habit.status = "pending"
                    habit.current_streak += 0
                else:
                    print(f"Habit {habit.task} status remains pending.")
                    habit.current_streak = 0
                if habit.periodicity == "daily":
                    next_pending_date = get_next_pending_date(habit.periodicity, now, habit.deadline_hour)
                elif habit.periodicity == "weekly":
                    next_pending_date = get_next_pending_date(habit.periodicity, now, habit.deadline_hour)

                habit.next_pending_date = next_pending_date 
                db.session.commit()
                print(f"Habit {habit.task} updated. Current streak: {habit.current_streak}")
                


scheduler.add_job(update_habit_statuses, 'interval', minutes=1)

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
    - deadline_hour (SelectField): The deadline hour field.
    - submit (SubmitField): The submit button.
    """

    habit_name = StringField(
        validators=[InputRequired()],
        render_kw={"placeholder": "Habit Name"}
    )
    periodicity = SelectField(
        "Periodicity",
        choices=[
            ("daily", "Daily"),
            ("weekly", "Weekly"),
        ],
        validators=[InputRequired()],
    )
    deadline_hour = SelectField(
        "Deadline Hour",
        choices=[(hour, f"{hour}:00") for hour in range(24)],
        validators=[InputRequired()]
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
        deadline_hour = int(form.deadline_hour.data)
        now = datetime.now()
        next_pending_date = get_next_pending_date(periodicity, now, deadline_hour)

        new_habit = Habit(
            user_id=current_user.id,
            task=habit_name,
            periodicity=periodicity,
            status="pending",
            added_date=now,
            next_pending_date=next_pending_date,
            deadline_hour=deadline_hour
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


@app.route('/complete_habit/<int:habit_id>', methods=['POST'])
def complete_habit(habit_id):
    """
    Mark a habit as completed and update related information.

    Args:
        habit_id (int): The ID of the habit to be marked as completed.

    """
    habit = Habit.query.get_or_404(habit_id) # Get the habit by its ID
    
    if current_user.id == habit.user_id:
        now = datetime.now()
        current_date = datetime.now().date()
        current_time = datetime.now()
        if now < habit.next_pending_date:
            habit.current_streak += 1 
            if habit.current_streak > habit.highest_streak:
                habit.highest_streak = habit.current_streak
            if habit.periodicity == "daily" and str(current_date.day) != habit.next_pending_date.strftime("%d"):
                habit.next_pending_date = get_next_pending_date(habit.periodicity, now, habit.deadline_hour)
            if str(current_date.day) == habit.next_pending_date.strftime("%d") and habit.periodicity =="daily":
             habit.next_pending_date = datetime(current_time.year, current_time.month, current_time.day, habit.deadline_hour, 0)
            elif habit.periodicity == "weekly" and str(current_date.day) == habit.next_pending_date.strftime("%d"):
                habit.next_pending_date = get_next_pending_date(habit.periodicity, now, habit.deadline_hour)
            elif habit.periodicity == "weekly" and str(current_date.day) < habit.next_pending_date.strftime("%d") :
                habit.next_pending_date = habit.next_pending_date
        else:
            habit.current_streak = 1  # Reset streak if habit wasn't completed in time
            habit.next_pending_date = get_next_pending_date(habit.periodicity, now, habit.deadline_hour)  # Recalculate next_pending_date

        habit.status = "checked"
        habit.last_completed = datetime.now()
        
        db.session.commit()
    
    return redirect(url_for('dashboard'))



@app.route('/delete_habit/<int:habit_id>', methods=['POST'])
def delete_habit(habit_id):
    """
    Delete a habit from the database.

    Args:
        habit_id (int): The ID of the habit to be deleted.

    Returns:
        Redirect: A redirect to the dashboard page.
    """
    habit = Habit.query.get_or_404(habit_id)
    
    if current_user.id == habit.user_id:
        db.session.delete(habit)
        db.session.commit()
    
    return redirect(url_for('dashboard'))

# Route for displaying habits the user struggled with
@app.route('/struggle_habits', methods=['GET'])
def struggle_habits():
    """
    Display habits that the user has struggled with.

    Returns:
        Response: The rendered HTML content for the struggle habits page or a redirect response.
    """
    if current_user.is_authenticated:
        user = current_user
        today = datetime.today()
        if today.day == 1:
            Habit.query.filter_by(user_id=user.id).update({"struggle_score": 0})
            db.session.commit()
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
        User.create_default_predefined_habits(new_user)
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)





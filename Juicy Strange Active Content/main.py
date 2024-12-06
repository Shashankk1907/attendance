from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'X7Ghfq8JdM2N9uLKWpaTB4z6vRQ5PEoYXj1CAsr3ZmtkOVyFgHwnDUcbleI'  # Replace with a strong secret key

login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Route for unauthenticated users

# User model (in-memory storage for this example)
class User(UserMixin):
    def __init__(self, id, username, password, is_admin=False):
        self.id = id
        self.username = username
        self.password = password
        self.is_admin = is_admin

# In-memory user storage
users = {"admin": {
            "id": 0,
            "username": "admin",
            "password": generate_password_hash("admin123"),  # Replace "admin123" with a secure password
            "attendance_data": {},  # Admin doesn't have attendance data
            "is_admin": True
        }} # {"username": {"id": ..., "password": "hashed_password", "attendance_data": {...}, "is_admin": bool}}
next_user_id = 1

@login_manager.user_loader
def load_user(user_id):
    for user_data in users.values():
        if str(user_data["id"]) == str(user_id):
            return User(user_data["id"], user_data["username"], user_data["password"], user_data["is_admin"])
    return None

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    if current_user.is_admin:
        return redirect(url_for("admin_dashboard"))
    if request.method == "POST":
        # Add a new subject (not directly related to updating attendance)
        subject = request.form.get("subject")
        user_data = users[current_user.username]
        if subject and subject not in user_data["attendance_data"]:
            user_data["attendance_data"][subject] = {"total_lectures": 0, "present": 0, "absent": 0}
    return render_template("index.html", attendance_data=users[current_user.username]["attendance_data"])

@app.route("/admin_dashboard")
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return "Unauthorized", 403
    return render_template("admin_dashboard.html", users=users)

@app.route("/admin_user_attendance/<username>")
@login_required
def admin_user_attendance(username):
    if not current_user.is_admin:
        return "Unauthorized", 403
    if username not in users:
        return "User not found", 404
    user_data = users[username]
    return render_template("admin_user_attendance.html", username=username, attendance_data=user_data["attendance_data"])

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username in users and check_password_hash(users[username]["password"], password):
            user = User(users[username]["id"], username, users[username]["password"], users[username]["is_admin"])
            login_user(user)
            return redirect(url_for("index"))
        else:
            return "Invalid username or password"
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        global next_user_id
        username = request.form.get("username")
        password = request.form.get("password")
        is_admin = request.form.get("is_admin") == "on"  # Checkbox for admin flag
        if username not in users:
            users[username] = {
                "id": next_user_id,
                "username": username,
                "password": generate_password_hash(password),
                "attendance_data": {},
                "is_admin": is_admin
            }
            next_user_id += 1
            return redirect(url_for("login"))
        else:
            return "Username already exists!"
    return render_template("register.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/mark/<subject>/<status>", methods=["POST"])
@login_required
def mark_attendance(subject, status):
    user_data = users[current_user.username]
    if subject in user_data["attendance_data"]:
        user_data["attendance_data"][subject]["total_lectures"] += 1
        if status == "present":
            user_data["attendance_data"][subject]["present"] += 1
        elif status == "absent":
            user_data["attendance_data"][subject]["absent"] += 1
        # Update attendance percentage
        total_lectures = user_data["attendance_data"][subject]["total_lectures"]
        present = user_data["attendance_data"][subject]["present"]
        user_data["attendance_data"][subject]["attendance_percentage"] = (
            round((present / total_lectures) * 100, 2)
            if total_lectures > 0
            else 0
        )
    return "OK", 200

@app.route("/attendance")
@login_required
def show_attendance():
    return render_template("attendance.html", attendance_data=users[current_user.username]["attendance_data"])

@app.route("/add_attendance_records", methods=["POST"])
@login_required
def add_attendance_records():
    user_data = users[current_user.username]
    attendance_updates = request.get_json()

    for record in attendance_updates:
        subject = record.get("subject")
        present = record.get("present", 0)
        absent = record.get("absent", 0)

        if subject in user_data["attendance_data"]:
            user_data["attendance_data"][subject]["present"] += present
            user_data["attendance_data"][subject]["absent"] += absent
            user_data["attendance_data"][subject]["total_lectures"] += (present + absent)
            # Update percentage
            total_lectures = user_data["attendance_data"][subject]["total_lectures"]
            present = user_data["attendance_data"][subject]["present"]
            user_data["attendance_data"][subject]["attendance_percentage"] = (
                round((present / total_lectures) * 100, 2)
                if total_lectures > 0
                else 0
            )
    return "OK", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

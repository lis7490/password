from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import secrets  # Добавляем для генерации токенов

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///flask.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "your-secret-key-here-" + secrets.token_hex(16)
db = SQLAlchemy(app)
migrate = Migrate(app, db)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    token = db.Column(db.String(100))
    token_expiration = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_token(self):
        self.token = secrets.token_urlsafe(32)
        self.token_expiration = datetime.utcnow() + timedelta(minutes=30)
        return self.token


class Notes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(64), nullable=False)
    text = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Note {self.title}>'


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_template("index.html")
    else:
        try:
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '').strip()

            # Валидация данных
            if not username or not email or not password:
                return render_template("index.html", error="Все поля обязательны для заполнения")

            if len(password) < 6:
                return render_template("index.html", error="Пароль должен содержать минимум 6 символов")

            # Проверяем существует ли пользователь
            if User.query.filter_by(email=email).first():
                return render_template("index.html", error="Пользователь с таким email уже существует")

            if User.query.filter_by(username=username).first():
                return render_template("index.html", error="Пользователь с таким именем уже существует")

            # Создаем нового пользователя
            new_user = User(username=username, email=email)
            new_user.set_password(password)
            new_user.generate_token()

            db.session.add(new_user)
            db.session.commit()

            session['token'] = new_user.token
            session['user_id'] = new_user.id
            session['username'] = new_user.username
            session['email'] = new_user.email


            return redirect(url_for('diary'))

        except Exception as e:
            print(f"Ошибка регистрации: {e}")  # Для отладки
            return render_template("index.html", error="Ошибка регистрации. Попробуйте еще раз.")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    else:
        try:
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '').strip()

            if not email or not password:
                return render_template('login.html', error="Все поля обязательны для заполнения")

            user = User.query.filter_by(email=email).first()
            if user and user.check_password(password):
                user.generate_token()
                db.session.commit()
                session['token'] = user.token
                session['user_id'] = user.id
                session['username'] = user.username
                session['email'] = user.email
                session['password_hash'] = user.password_hash
                return redirect(url_for('diary'))
            else:
                return render_template('login.html', error="Неверный email или пароль")

        except Exception as e:
            print(f"Ошибка входа: {e}")  # Для отладки
            return render_template('login.html', error="Ошибка входа. Попробуйте еще раз.")


@app.before_request
def check_auth():
    # Страницы, которые не требуют аутентификации
    public_endpoints = ['static', 'index', 'login', 'logout']

    if request.endpoint in public_endpoints:
        return

    token = session.get("token")
    user_id = session.get("user_id")

    if not token or not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user or user.token != token or datetime.utcnow() > user.token_expiration:
        session.clear()
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/home")
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template("home.html", username=session.get('username'))


@app.route("/дневник_программиста", methods=['POST', 'GET'])
def diary():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        text = request.form.get('text', '').strip()

        if title and text:
            new_note = Notes(title=title, text=text)
            db.session.add(new_note)
            db.session.commit()
            return redirect(url_for('diary'))

    all_notes = Notes.query.order_by(Notes.created_at.desc()).all()
    return render_template("notes.html", notes=all_notes, username=session.get('username'))


@app.route("/удалить_запись/<int:note_id>", methods=['POST'])
def delete_note(note_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    note_to_delete = Notes.query.get_or_404(note_id)
    db.session.delete(note_to_delete)
    db.session.commit()
    return redirect(url_for('diary'))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
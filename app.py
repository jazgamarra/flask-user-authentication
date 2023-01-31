from flask import Flask, render_template, url_for, redirect 
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length
from flask_bcrypt import Bcrypt

# Creamos la aplicacion
app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Conectar a la base de datos que creamos 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db' 
app.config['SECRET_KEY'] = 'jamin'

# Configurar el login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Cargar el usuario actual de la sesion actual
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) 

# --------------------------------------------------------------------------------------------------------------
# CLASES 
# --------------------------------------------------------------------------------------------------------------

# Creamos la clase User para la base de datos 
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(60), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

# Creamos la clase SignupForm para crear el formulario de registro de usuarios nuevos
class SignupForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Nombre de usuario"})
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Contrasenha"})
    submit = SubmitField('Crear cuenta')

    # Validar que el usuario no exista ya en la base de datos
    def validar_username(self, username):
        existe_el_usuario = User.query.filter_by(username=username.data).first()
        
        if existe_el_usuario:
            return '<h1> El usuario ya existe, por favor elija otro </h1>'

# Creamos el formulario para el inicio de sesion de usuarios registrados 
class LoginForm (FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Nombre de usuario"})
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Contrasenha"})
    submit = SubmitField('Iniciar sesion')

# --------------------------------------------------------------------------------------------------------------
# ENDPOINTS 
# --------------------------------------------------------------------------------------------------------------
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    # The validate_on_submit() method returns True when the form was submitted and the data was accepted by all the field validators. 
    if form.validate_on_submit():
        # Verifica si el usuario existe en la base de datos
        user = User.query.filter_by(username=form.username.data).first()

        # Si el usuario existe, verifica si la contrasenha es correcta
        if user: 
            # Si la contrasenha es correcta, inicia sesion
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard')) 
            else:
                return '<h1> Contrasenha incorrecta </h1>'
        else:
            return '<h1> El usuario no existe </h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()

    if form.validate_on_submit():
        # Extraer los datos del formulario
        usuario = form.username.data
        contrasenha = form.password.data

        # Hashear la contrasenha
        contrasenha_hasheada = bcrypt.generate_password_hash(contrasenha).decode('utf-8')

        # Crear el usuario en la base de datos
        new_user = User(username=usuario, password=contrasenha_hasheada)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    username = current_user.username
    return render_template('dashboard.html', username = username) 

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home')) 

# Correr el servidor
if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
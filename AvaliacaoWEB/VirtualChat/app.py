from flask import (Flask, render_template, request, redirect, 
    url_for, flash)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
app = Flask(__name__)

app.config['SECRET_KEY'] = 'IFSC2025'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///VirtualChat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    contato = db.relationship('Contato', backref='user', lazy=True)
    mensagem = db.relationship('Mensagem', backref='user', lazy=True)

class Contato(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    celular = db.Column(db.String(12), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    mensagem = db.relationship('Mensagem', backref='contato', lazy=True)

class Mensagem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(150), nullable=False)
    texto = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    contato_id = db.Column(db.Integer, db.ForeignKey('contato.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET'])
@login_required
def home():
    contatos = Contato.query.filter_by(user_id=current_user.id).all()
    contato_id = request.args.get('contato_id')
    contato_selecionado = None
    mensagens = []
    if contato_id:
        contato_selecionado = Contato.query.filter_by(id=contato_id, user_id=current_user.id).first()
        if contato_selecionado:
            mensagens = Mensagem.query.filter_by(user_id=current_user.id, contato_id=contato_id).all()
    return render_template('home.html', contatos=contatos, contato_selecionado=contato_selecionado, mensagens=mensagens)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Usuário não existe!')
            return redirect(url_for('login'))
        if not check_password_hash(user.password, password):
            flash("Senha inválida!")
            return redirect(url_for('login'))
        
        login_user(user)
        return redirect(url_for('home'))
        
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password1 = request.form['password1']
        password2 = request.form['password2']
        erros = []
        if len(name) < 2:
            erros.append('Nome deve ter pelo menos 2 caracteres')
        if  email.find('@') == -1:
            erros.append('Email inválido')
        if len(password1) < 8:
            erros.append('A senha deve ter pelo menos 8 caracteres')
        if password1 != password2:
            erros.append('As senhas devem ser iguais')
        
        if len(erros) > 0:
            return render_template('signup.html', erros=erros, name=name, email=email)
        else:
            senha_hash = generate_password_hash(password1)
            user = User(name=name, email=email, password=senha_hash)
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('home'))
    
    return render_template('signup.html')

@app.route('/contato', methods=['GET', 'POST'])
@login_required
def contato():
    
    if request.method == 'POST':
        name = request.form['nomeContato']
        email = request.form['email']
        celular = request.form['celular']
        erros = []
        if len(name) < 2:
            erros.append('Nome deve ter pelo menos 2 caracteres')
        if  email.find('@') == -1:
            erros.append('Email inválido')
        if len(celular) < 8:
            erros.append('Celular inválido')
        if len(erros) > 0:
            return render_template('contato.html', erros=erros, name=name, email=email)
        else:
            contato = Contato(name=name, email=email, celular=celular, user_id=current_user.id)

            db.session.add(contato)
            db.session.commit()
            return redirect(url_for('home'))
    
    return render_template('contato.html')

@app.route('/mensagem', methods=['POST'])
@login_required
def enviar_mensagem():
    contato_id = request.form['contato_id']
    titulo = request.form['titulo']
    texto = request.form['texto']
    # Verifica se o contato existe e pertence ao usuário logado
    contato = Contato.query.filter_by(id=contato_id, user_id=current_user.id).first()
    if not contato:
        flash('Contato inválido!')
        return redirect(url_for('home'))

    nova_mensagem = Mensagem(
        titulo=titulo,
        texto=texto,
        user_id=current_user.id,
        contato_id=contato_id
    )
    db.session.add(nova_mensagem)
    db.session.commit()
    return redirect(url_for('home', contato_id=contato_id))

@app.route('/excluir_contato/<int:contato_id>', methods=['POST'])
@login_required
def excluir_contato(contato_id):
    contato = Contato.query.filter_by(id=contato_id, user_id=current_user.id).first()
    if not contato:
        flash('Contato não encontrado ou não pertence a você.')
        return redirect(url_for('home'))

    # Remove também as mensagens associadas a esse contato (opcional, mas recomendado)
    Mensagem.query.filter_by(contato_id=contato_id).delete()
    db.session.delete(contato)
    db.session.commit()
    flash('Contato excluído com sucesso!')
    return redirect(url_for('home'))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


def create_tables():
    with app.app_context():
        db.create_all()

if __name__ == "__main__":
    # import os
    # if not os.path.isfile(os.path.join(os.path.abspath(__file__), 'VirtualChat.db')):
    #     create_tables()
    create_tables()
    app.run(debug=True)
from flask import Flask, render_template, url_for, request, redirect, flash, make_response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config['SECRET_KEY'] = 'sdfsdfs321dfdfgdfg12435dfvg'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///base.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

users = {'admin': generate_password_hash('adminpass')}

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(username):
    return User(username) if username in users else None

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_password = users.get(username)

        if user_password and check_password_hash(user_password, password):
            user = User(username)
            login_user(user)
            return redirect(url_for('admin' if username == 'admin' else 'content'))
        else:
            flash('Неверное имя пользователя или пароль.')

    return render_template('login.html')


class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    number_certificate = db.Column(db.Text, nullable=False)
    item_category = db.Column(db.Text, nullable=False)
    item_brand = db.Column(db.Text, nullable=False)
    case_submitted_time = db.Column(db.Text, nullable=False)
    case_completed = db.Column(db.Text, nullable=False)
    image_data1 = db.Column(db.String, nullable=False)
    image_data2 = db.Column(db.String, nullable=False)
    image_data3 = db.Column(db.String, nullable=False)
    image_data4 = db.Column(db.String, nullable=False)
    image_data5 = db.Column(db.String, nullable=False)
    image_data6= db.Column(db.String, nullable=False)
    image_qr= db.Column(db.String, nullable=False)


    def __repr__(self):
        return '<Article %r' % self.id


@app.route('/')
def index():
    return (render_template('index.html'))

@app.route('/posts/<number_certificate>/imgobr1')
def imgobr1(number_certificate):
    articles = Article.query.filter_by(number_certificate=number_certificate).first()
    h = articles.image_data1
    n = make_response(h)
    n.headers['Content-Type'] = 'image/png'
    return n

@app.route('/posts/<number_certificate>/imgobr2')
def imgobr2(number_certificate):
    articles = Article.query.filter_by(number_certificate=number_certificate).first()
    h = articles.image_data2
    n = make_response(h)
    n.headers['Content-Type'] = 'image/png'
    return n

@app.route('/posts/<number_certificate>/imgobr3')
def imgobr3(number_certificate):
    articles = Article.query.filter_by(number_certificate=number_certificate).first()
    h = articles.image_data3
    n = make_response(h)
    n.headers['Content-Type'] = 'image/png'
    return n

@app.route('/posts/<number_certificate>/imgobr4')
def imgobr4(number_certificate):
    articles = Article.query.filter_by(number_certificate=number_certificate).first()
    h = articles.image_data4
    n = make_response(h)
    n.headers['Content-Type'] = 'image/png'
    return n
@app.route('/posts/<number_certificate>/imgobr5')
def imgobr5(number_certificate):
    articles = Article.query.filter_by(number_certificate=number_certificate).first()
    h = articles.image_data5
    n = make_response(h)
    n.headers['Content-Type'] = 'image/png'
    return n
@app.route('/posts/<number_certificate>/imgobr6')
def imgobr6(number_certificate):
    articles = Article.query.filter_by(number_certificate=number_certificate).first()
    h = articles.image_data6
    n = make_response(h)
    n.headers['Content-Type'] = 'image/png'
    return n
@app.route('/posts/<number_certificate>/imgobr_qr')
def imgobr_qr(number_certificate):
    articles = Article.query.filter_by(number_certificate=number_certificate).first()
    h = articles.image_qr
    n = make_response(h)
    n.headers['Content-Type'] = 'image/png'
    return n

@app.route('/search-certificate', methods=['POST', 'GET'])
def search_certificate():
    if request.method == 'POST':
        number_certificate_search = request.form['number_certificate']
        article = Article.query.filter_by(number_certificate=number_certificate_search).first_or_404()
        if article.number_certificate == number_certificate_search:
            return redirect(f'/posts/{article.number_certificate}')

    return render_template('search-certificate.html')


@app.route('/posts', methods=['GET', 'POST'])
@login_required
def posts():
    articles = Article.query.order_by(Article.number_certificate).all()
    return render_template('posts.html', articles=articles)

@app.route('/posts/<number_certificate>')
def posts_legit(number_certificate):
    article = Article.query.filter_by(number_certificate=number_certificate).first_or_404()
    if article:
        return render_template('legit.html', article=article)

@app.route('/posts/<string:number_certificate>/del')
@login_required
def posts_delete(number_certificate):
    article = Article.query.filter_by(number_certificate=number_certificate).first_or_404()
    try:
        db.session.delete(article)
        db.session.commit()
        return redirect('/posts')
    except:
        return "Error"

@app.route('/posts/<string:number_certificate>/update', methods=['POST', 'GET'])
@login_required
def post_update(number_certificate):
    article = Article.query.filter_by(number_certificate=number_certificate).first_or_404()
    if request.method == 'POST':
        article.number_certificate = request.form['number_certificate']
        article.item_category = request.form['item_category']
        article.item_brand = request.form['item_brand']
        article.case_submitted_time = request.form['case_submitted_time']
        article.case_completed = request.form['case_completed']

        file1 = request.files['file1']
        file2 = request.files['file2']
        file3 = request.files['file3']
        file4 = request.files['file4']
        file5 = request.files['file5']
        file6 = request.files['file6']
        file7 = request.files['file7']

        article.image_data1 = file1.read()
        article.image_data2 = file2.read()
        article.image_data3 = file3.read()
        article.image_data4 = file4.read()
        article.image_data5 = file5.read()
        article.image_data6 = file6.read()
        article.image_qr = file7.read()

        try:
            db.session.commit()
            return redirect('/posts')
        except:
            return "Ошибка"
    else:

        return render_template('post_update.html', article=article)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if current_user.id != 'admin':
        return redirect(url_for('index'))
    if request.method == 'POST':
        number_certificate = request.form['number_certificate']
        item_category = request.form['item_category']
        item_brand = request.form['item_brand']
        case_submitted_time = request.form['case_submitted_time']
        case_completed = request.form['case_completed']
        file1 = request.files['file1']
        file2 = request.files['file2']
        file3 = request.files['file3']
        file4 = request.files['file4']
        file5 = request.files['file5']
        file6 = request.files['file6']
        file7 = request.files['file7']

        image_data1 = file1.read()
        image_data2 = file2.read()
        image_data3 = file3.read()
        image_data4 = file4.read()
        image_data5 = file5.read()
        image_data6 = file6.read()
        image_qr = file7.read()


        article = Article(item_category=item_category,
                          item_brand=item_brand,
                          case_submitted_time=case_submitted_time,
                          case_completed=case_completed,
                          image_data1 = image_data1,
                          image_data2 = image_data2,
                          image_data3 = image_data3,
                          image_data4 = image_data4,
                          image_data5 = image_data5,
                          image_data6 = image_data6,
                          image_qr = image_qr,
                          number_certificate = number_certificate
                          )

        try:
            db.session.add(article)
            db.session.commit()
            return redirect('/posts')
        except:
            return "Ошибка"
    else:
        return render_template('admin.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

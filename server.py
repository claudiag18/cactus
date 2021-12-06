# IMPORTS
from flask import Flask, render_template, request, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask import abort
from functools import wraps
from flask_gravatar import Gravatar
from dotenv import load_dotenv
load_dotenv()
import os
import stripe


# CREATE WEBAPP
app = Flask(__name__)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///store.db'
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# CONFIGURE USER TABLE IN DATABASE
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))


# CONFIGURE PRODUCT TABLE IN DATABASE
class Product(db.Model):
    __tablename__ = "products"
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(250))
    description = db.Column(db.String(250))
    img_file = db.Column(db.String(250))
    price_text = db.Column(db.String(250))
    display = db.Column(db.String(250))


# GLOBAL VARIABLES
CART_LIST = []
DOMAIN = 'http://localhost:5000'

# SETTING UP STRIPE
stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")


# LOGIN MANAGER OBJECT
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or int(current_user.id) != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


# LOGIN PAGE
@app.route('/login', methods=['GET', 'POST'])
def login():
    global CART_LIST
    num_items = len(CART_LIST)
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('This email address has not been registered.')
            return redirect(url_for('register'))
        elif check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('The password provided is incorrect.')
    return render_template("login.html", current_user=current_user, num_items=num_items)


# CHANGE PASSWORD PAGE
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    global CART_LIST
    num_items = len(CART_LIST)
    if request.method == 'POST':
        password_1 = request.form.get('password_1')
        password_2 = request.form.get('password_2')
        if password_1 == password_2:
            user_id = current_user.id
            user_to_update = User.query.get(user_id)
            hash_salted_password = generate_password_hash(password_1, method='pbkdf2:sha256', salt_length=8)
            user_to_update.password = hash_salted_password
            db.session.commit()
            logout_user()
            flash('Your password has been updated sucessfully. Please log in again')
            return redirect(url_for('login'))
        else:
            flash('Please make sure your password is consistent.')
            redirect(url_for('change_password'))

    return render_template("change_password.html", current_user=current_user, num_items=num_items)


# REGISTER PAGE
@app.route('/register', methods=['GET', 'POST'])
def register():
    global CART_LIST
    num_items = len(CART_LIST)
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        password2 = request.form.get('password2')
        if User.query.filter_by(email=email).first():
            flash("This email addressed has been already registered")
            return redirect(url_for('login'))
        elif password2 != password:
            flash("Please confirm your password")
        else:
            hash_salted_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
            new_user = User(
                email=email,
                password=hash_salted_password,
            )
            db.session.add(new_user)
            db.session.commit()
            # Log in and authenticate user after adding details to database.
            login_user(new_user)
            return redirect(url_for("home"))

    return render_template("register.html", current_user=current_user, num_items=num_items)


# LOGOUT PAGE
@app.route('/logout')
@login_required
def logout():
    global CART_LIST
    logout_user()
    CART_LIST = []
    return redirect(url_for('home'))


# HOME PAGE
@app.route("/")
def home():
    global CART_LIST
    num_items = len(CART_LIST)
    return render_template('index.html', num_items=num_items)


@app.route("/<id>")
def product(id):
    global CART_LIST
    num_items = len(CART_LIST)
    products = Product.query.filter_by(category=id).all()
    title = id.split('_')[0].upper() + " " + id.split('_')[1].upper()
    return render_template('product.html', page=title, products=products, num_items=num_items)


@app.route('/cart/<int:id>', methods=['GET', 'POST'])
def cart(id):
    global CART_LIST
    total_cost = 0
    if id == 9999999:
        num_items = len(CART_LIST)
    else:
        if request.method == 'POST':
            name = str(id)
            if request.form.get(name):
                num_cart = request.form.get(name)
                for product in CART_LIST:
                    if product['id'] == id:
                        product['num_cart'] = num_cart
        else:
            num_cart = 1
            product = Product.query.get(id)
            product_dict = {
                'id': product.id,
                'category': product.category,
                'description': product.description,
                'img_file': product.img_file,
                'price_text': product.price_text,
                'display': product.display,
                'num_cart': num_cart,
            }
            CART_LIST.append(product_dict)
        num_items = len(CART_LIST)
    for product in CART_LIST:
        cost = float(product['price_text']) * int(product['num_cart'])
        total_cost += cost
    total_cost = round(total_cost, 2)
    return render_template('cart.html', products=CART_LIST, num_items=num_items, total_cost=total_cost)


@app.route('/remove/<int:prod_id>')
def remove(prod_id):
    global CART_LIST
    total_cost = 0
    for product in CART_LIST:
        if product['id'] == prod_id:
            CART_LIST.remove(product)
    num_items = len(CART_LIST)
    for product in CART_LIST:
        cost = float(product['price_text']) * int(product['num_cart'])
        total_cost += round(cost, 2)
    return render_template('cart.html', products=CART_LIST, num_items=num_items, total_cost=total_cost)


@app.route('/checkout/<final_cost>', methods=['GET', 'POST'])
def checkout(final_cost):
    global CART_LIST
    num_items = len(CART_LIST)
    return render_template('checkout.html', products=CART_LIST, num_items=num_items, cost=final_cost)


@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    final_num = float(request.values.get('cost'))
    final_num = int(final_num*100)
    try:
        checkout_session = stripe.checkout.Session.create(
            line_items=[
                {
                    # Provide the exact Price ID (for example, pr_1234) of the product you want to sell
                    'price_data': {
                        'currency': 'usd',
                        'product_data': {
                            'name': 'Your Cactus Purchase',
                        },
                        'unit_amount': final_num,
                    },
                    'quantity': 1,
                },
            ],
            mode='payment',
            success_url=DOMAIN + '/success',
            cancel_url=DOMAIN + '/cancel',
        )
    except Exception as e:
        return str(e)

    return redirect(checkout_session.url, code=303)


@app.route('/success')
def success():
    return render_template('success.html')


@app.route('/cancel')
def cancel():
    return render_template('cancel.html')

if __name__ == "__main__":
    app.run(debug=True)
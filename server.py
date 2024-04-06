from flask import Flask, request, jsonify
import sqlite3
import bcrypt

app = Flask(__name__)

# Database Functions
def init_db():
    with sqlite3.connect('application.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price REAL, quantity INTEGER)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS feedbacks (username TEXT, content TEXT)''')

        # Add Admin
        cursor.execute("SELECT * FROM users WHERE username='admin'")
        admin_exists = cursor.fetchone()
        if not admin_exists:
            admin_pass = bcrypt.hashpw('123asd!@#ASD'.encode('utf-8'), bcrypt.gensalt())
            cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("admin", admin_pass, "admin"))
        conn.commit()

# Account Functions
@app.route('/register', methods=['POST'])
def register():
    username = request.json['username']
    password = request.json['password']
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    role = 'customer'
    with sqlite3.connect('application.db') as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_password, role))
            conn.commit()
            return jsonify({'message': 'Customer registered successfully'}), 200
        except sqlite3.IntegrityError as e:
            return jsonify({'message': 'Username already exists'}), 400
        except Exception as e:
            return jsonify({'message': str(e)}), 400

def authenticate(username, password):
    with sqlite3.connect('application.db') as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        user = cursor.fetchone()
        if user:
            if bcrypt.checkpw(password.encode('utf-8'), user['password']):
                return user['role']
        else:
            return False
    
@app.route('/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']
    if authenticate(username, password) == 'admin':
        return jsonify({'message': 'Login successful', 'role':'admin'}), 200
    elif authenticate(username, password) == 'user':
        return jsonify({'message': 'Login successful', 'role':'user'}), 200
    elif authenticate(username, password) == 'customer':
        return jsonify({'message': 'Login successful', 'role':'customer'}), 200
    else:
        return jsonify({'message': 'Invalid username or password', 'role': 'None'}), 401
    
@app.route('/change_password', methods=['POST'])
def change_password():
    try:
        username = request.json['username']
        old_password = request.json['old_password']
        new_password = request.json['new_password']
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        if authenticate(username, old_password):
            with sqlite3.connect('application.db') as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, username))
                conn.commit()
            return jsonify({'message': 'Password changed successfully'}), 200
        else:
            return jsonify({'message': 'Authentication failed'}), 401
    except Exception as e:
        return jsonify({'message': str(e)}), 400

# Admin Functions
@app.route('/add_user', methods=['POST'])
def add_user():
    try:
        username = request.json['username']
        password = request.json['password']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        role = 'user'
        with sqlite3.connect('application.db') as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_password, role))
            conn.commit()
        return jsonify({'message': 'User added successfully'}), 201
    except Exception as e:
        return jsonify({'message': str(e)}), 400
    
@app.route('/view_feedbacks', methods=['GET'])
def view_feedbacks():
    with sqlite3.connect('application.db') as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM feedbacks")
        feedbacks = cursor.fetchall()
        feedback_list = [{'username': fb['username'], 'content': fb['content']} for fb in feedbacks]
        print(feedback_list)
        return jsonify(feedback_list)

# Admin/User Functions
@app.route('/add_product', methods=['POST'])
def add_product():
    try:
        name = request.json['name']
        price = float(request.json['price'])
        quantity = int(request.json['quantity'])
        if quantity <= 0 or price <= 0:
            return jsonify({'message': 'The quantity must be a non-negative integer.'}), 400
        else:
            with sqlite3.connect('application.db') as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO products (name, price, quantity) VALUES (?, ?, ?)", (name, price, quantity))
                conn.commit()
            return jsonify({'message': 'Product added successfully'}), 201
    except Exception as e:
        message = 'Please input a float for price and an integer for quantity. ' + str(e)
        return jsonify({'message': message}), 400

# Customer Functions
@app.route('/view_products', methods=['GET'])
def view_products():
    try:
        with sqlite3.connect('application.db') as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT id, name, price, quantity FROM products")
            products = cursor.fetchall()
            products_list = [dict(row) for row in products]
        return jsonify({'products': products_list}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 400
    
@app.route('/buy_product', methods=['POST'])
def buy_product():
    try:
        product_id = request.json['product_id']
        quantity = int(request.json['quantity'])
        if quantity <= 0:
            return jsonify({'message': 'The quantity must be a non-negative integer.'}), 400
        with sqlite3.connect('application.db') as conn:
            c = conn.cursor()
            c.execute("SELECT quantity FROM products WHERE id = ?", (product_id,))
            product_quantity = c.fetchone()[0]
            if product_quantity >= quantity:
                new_quantity = product_quantity - quantity
                c.execute("UPDATE products SET quantity = ? WHERE id = ?", (new_quantity, product_id))
                conn.commit()
                return jsonify({'message': 'Product purchased successfully'}), 200
            else:
                return jsonify({'message': 'Not enough product in stock'}), 400
    except Exception as e:
        message = 'Please input an integer for quantity. ' + str(e)
        return jsonify({'message': message}), 400
    
@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    try:
        username = request.json['username']
        content = request.json['content']
        with sqlite3.connect('application.db') as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO feedbacks (username, content) VALUES (?, ?)", (username, content))
            conn.commit()
        return jsonify({'message': 'Feedback submitted successfully'}), 201
    except Exception as e:
        return jsonify({'message': str(e)}), 400

# Main
if __name__ == '__main__':
    init_db()
    app.run(debug=True)

from flask import Flask, request, render_template, redirect, url_for, session, g
import sqlite3
import bcrypt
import os
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)
app.secret_key = os.urandom(24)


DATABASE = 'database.db'

def get_db():
    if not hasattr(g, 'db'):
        g.db = sqlite3.connect(DATABASE)
    return g.db

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db'):
        g.db.close()

def init_db():
    conn = sqlite3.connect(DATABASE)
    conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)')
    conn.execute('CREATE TABLE IF NOT EXISTS topics (id INTEGER PRIMARY KEY, title TEXT, content TEXT, author TEXT)')
    conn.execute('CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, content TEXT, topic_id INTEGER, author TEXT)')
    conn.close()

@app.route('/')
def index():
    conn = get_db()
    cursor = conn.execute('SELECT * FROM topics')
    topics = cursor.fetchall()
    return render_template('index.html', topics=topics)

@app.route('/register', methods=['GET'])
def register_get():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register_post():
    username = request.form['username']
    password = request.form['password']
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        conn = get_db()
        conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        return "User alredy exists", 400
    return redirect(url_for('login'))

@app.route('/login', methods=['GET'])
def login_get():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    username = request.form['username']
    password = request.form['password']
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):
        session['username'] = username
        return redirect(url_for('index'))
    return "Invalid credentials", 401

@app.route('/new_topic', methods=['GET'])
def new_topic_get():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('new_topic.html')

@app.route('/new_topic', methods=['POST'])
def new_topic_post():
    title = request.form['title']
    content = request.form['content']
    author = session['username']
    conn = get_db()
    conn.execute('INSERT INTO topics (title, content, author) VALUES (?, ?, ?)', (title, content, author))
    conn.commit()
    return redirect(url_for('index'))

@app.route('/topic/<int:topic_id>', methods=['GET'])
def topic_get(topic_id):
    conn = get_db()
    topic = conn.execute('SELECT * FROM topics WHERE id = ?', (topic_id,)).fetchone()
    comments = conn.execute('SELECT * FROM comments WHERE topic_id = ?', (topic_id,)).fetchall()
    return render_template('topic.html', topic=topic, comments=comments)

@app.route('/topic/<int:topic_id>', methods=['POST'])
def topic_post(topic_id):
    conn = get_db()
    if 'username' not in session:
        return redirect(url_for('login_get'))
    content = request.form['content']
    author = session.get('username', 'Guest')
    conn.execute('INSERT INTO comments (content, topic_id, author) VALUES (?, ?, ?)', (content, topic_id, author))
    conn.commit()
    topic = conn.execute('SELECT * FROM topics WHERE id = ?', (topic_id,)).fetchone()
    comments = conn.execute('SELECT * FROM comments WHERE topic_id = ?', (topic_id,)).fetchall()
    return render_template('topic.html', topic=topic, comments=comments)

@app.route('/edit_comment/<int:comment_id>', methods=['GET'])
def edit_comment_get(comment_id):
    if 'username' not in session:
        return redirect(url_for('login_get'))
    return edit_item_get('comments', comment_id)

@app.route('/edit_comment/<int:comment_id>', methods=['POST'])
def edit_comment_post(comment_id):
    if 'username' not in session:
        return redirect(url_for('login_get'))
    return edit_item_post('comments', comment_id, 'content')

@app.route('/edit_topic/<int:topic_id>', methods=['GET'])
def edit_topic_get(topic_id):
    if 'username' not in session:
        return redirect(url_for('login_get'))
    return edit_item_get('topics', topic_id)

@app.route('/edit_topic/<int:topic_id>', methods=['POST'])
def edit_topic_post(topic_id):
    if 'username' not in session:
        return redirect(url_for('login_get'))
    return edit_item_post('topics', topic_id, 'title', 'content')

def edit_item_get(table, item_id):
    conn = get_db()
    item = conn.execute(f'SELECT * FROM {table} WHERE id = ?', (item_id,)).fetchone()
    return render_template(f'edit_{table[:-1]}.html', **{table[:-1]: item})

def edit_item_post(table, item_id, *fields):
    conn = get_db()
    data = {field: request.form[field] for field in fields}
    author = session['username']
    item = conn.execute(f'SELECT * FROM {table} WHERE id = ? AND author = ?', (item_id, author)).fetchone()
    if not item:
        return "Permissão negada", 403
    set_clause = ', '.join([f"{field} = ?" for field in fields])
    conn.execute(f'UPDATE {table} SET {set_clause} WHERE id = ?', (*data.values(), item_id))
    conn.commit()
    return redirect(url_for('index'))

@app.route('/delete_comment/<int:comment_id>')
def delete_comment(comment_id):
    return delete_item('comments', comment_id)

@app.route('/delete_topic/<int:topic_id>')
def delete_topic(topic_id):
    return delete_item('topics', topic_id)

def delete_item(table, item_id):
    if 'username' not in session:
        return redirect(url_for('login_get'))
    conn = get_db()
    author = session['username']
    item = conn.execute(f'SELECT * FROM {table} WHERE id = ? AND author = ?', (item_id, author)).fetchone()
    if not item:
        return "Permissão negada", 403
    conn.execute(f'DELETE FROM {table} WHERE id = ?', (item_id,))
    if table == 'topics':
        conn.execute('DELETE FROM comments WHERE topic_id = ?', (item_id,))
    conn.commit()
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=False)
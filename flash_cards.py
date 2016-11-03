import os
import sqlite3
import binascii
import hashlib
import errno
import uuid
from flask import Flask, request, session, g, redirect, url_for, abort, \
    render_template, flash

app = Flask(__name__)
app.config.from_object(__name__)
authenticated = {}

def connect_db(db=None):
    print(db)
    if db is None:
        if not 'session_id' in session or not session['session_id'] in authenticated:
            return None
    try:
        os.makedirs(os.path.join(app.root_path, 'db'))
    except OSError as exception:
        if exception.errno != errno.EEXIST:
            raise
    if db is None:
        db = app.config['USERS'][authenticated[session['session_id']]]['DATABASE']
    rv = sqlite3.connect(db)
    rv.row_factory = sqlite3.Row
    return rv

def init_user_db():
    db = connect_db(os.path.join(app.root_path, 'db', 'users.db'))
    if db:
        with app.open_resource('data/user.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()
    else:
        print("Could not get database handler")

def init_db():
    db = get_db()
    if db:
        with app.open_resource('data/schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()
    else:
        print("Could not get database handler")


def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    db_handler = connect_db()
    if not db_handler:
        return None
    if not hasattr(g, 'sqlite_db'):
        g.sqlite_db = db_handler
    return g.sqlite_db


@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()


@app.route('/initdb')
def initdb():
    init_db()
    flash("Initialized database")
    return redirect(url_for('general'))


@app.route('/')
def index():
    if 'session_id' in session and session['session_id'] in authenticated:
        return redirect(url_for('general'))
    else:
        return redirect(url_for('login'))


@app.route('/cards')
def cards():
    if not 'session_id' in session or not session['session_id'] in authenticated:
        return redirect(url_for('login'))
    db = get_db()
    query = '''
        SELECT id, type, front, back, known
        FROM cards
        ORDER BY id DESC
    '''
    cur = db.execute(query)
    cards = cur.fetchall()
    return render_template('cards.html', cards=cards, filter_name="all")


@app.route('/filter_cards/<filter_name>')
def filter_cards(filter_name):
    if not 'session_id' in session or not session['session_id'] in authenticated:
        return redirect(url_for('login'))

    filters = {
        "all":      "where 1 = 1",
        "general":  "where type = 1",
        "code":     "where type = 2",
        "known":    "where known = 1",
        "unknown":  "where known = 0",
    }

    query = filters.get(filter_name)

    if not query:
        return redirect(url_for('cards'))

    db = get_db()
    fullquery = "SELECT id, type, front, back, known FROM cards " + query + " ORDER BY id DESC"
    cur = db.execute(fullquery)
    cards = cur.fetchall()
    return render_template('cards.html', cards=cards, filter_name=filter_name)


@app.route('/add', methods=['POST'])
def add_card():
    if not 'session_id' in session or not session['session_id'] in authenticated:
        return redirect(url_for('login'))
    db = get_db()
    db.execute('INSERT INTO cards (type, front, back) VALUES (?, ?, ?)',
               [request.form['type'],
                request.form['front'],
                request.form['back']
                ])
    db.commit()
    flash('New card was successfully added.')
    return redirect(url_for('cards'))


@app.route('/edit/<card_id>')
def edit(card_id):
    if not 'session_id' in session or not session['session_id'] in authenticated:
        return redirect(url_for('login'))
    db = get_db()
    query = '''
        SELECT id, type, front, back, known
        FROM cards
        WHERE id = ?
    '''
    cur = db.execute(query, [card_id])
    card = cur.fetchone()
    return render_template('edit.html', card=card)


@app.route('/edit_card', methods=['POST'])
def edit_card():
    if not 'session_id' in session or not session['session_id'] in authenticated:
        return redirect(url_for('login'))
    selected = request.form.getlist('known')
    known = bool(selected)
    db = get_db()
    command = '''
        UPDATE cards
        SET
          type = ?,
          front = ?,
          back = ?,
          known = ?
        WHERE id = ?
    '''
    db.execute(command,
               [request.form['type'],
                request.form['front'],
                request.form['back'],
                known,
                request.form['card_id']
                ])
    db.commit()
    flash('Card saved.')
    return redirect(url_for('cards'))


@app.route('/delete/<card_id>')
def delete(card_id):
    if not 'session_id' in session or not session['session_id'] in authenticated:
        return redirect(url_for('login'))
    db = get_db()
    db.execute('DELETE FROM cards WHERE id = ?', [card_id])
    db.commit()
    flash('Card deleted.')
    return redirect(url_for('cards'))


@app.route('/general')
@app.route('/general/<card_id>')
def general(card_id=None):
    if not 'session_id' in session or not session['session_id'] in authenticated:
        return redirect(url_for('login'))
    return memorize("general", card_id)


@app.route('/code')
@app.route('/code/<card_id>')
def code(card_id=None):
    if not 'session_id' in session or not session['session_id'] in authenticated:
        return redirect(url_for('login'))
    return memorize("code", card_id)


def memorize(card_type, card_id):
    if card_type == "general":
        type = 1
    elif card_type == "code":
        type = 2
    else:
        return redirect(url_for('cards'))

    if card_id:
        card = get_card_by_id(card_id)
    else:
        card = get_card(type)
    if not card:
        flash("You've learned all the " + card_type + " cards.")
        return redirect(url_for('cards'))
    short_answer = (len(card['back']) < 75)
    return render_template('memorize.html',
                           card=card,
                           card_type=card_type,
                           short_answer=short_answer)


def get_card(type):
    db = get_db()

    query = '''
      SELECT
        id, type, front, back, known
      FROM cards
      WHERE
        type = ?
        and known = 0
      ORDER BY RANDOM()
      LIMIT 1
    '''

    cur = db.execute(query, [type])
    return cur.fetchone()


def get_card_by_id(card_id):
    db = get_db()

    query = '''
      SELECT
        id, type, front, back, known
      FROM cards
      WHERE
        id = ?
      LIMIT 1
    '''

    cur = db.execute(query, [card_id])
    return cur.fetchone()


def retrieve_users():
    users = {}
    db = connect_db(os.path.join(app.root_path, 'db', 'users.db'))
    
    if db:
        try:
            query = '''
              SELECT
                username, password
              FROM users
            '''

            cur = db.execute(query)
            rows = cur.fetchall()
            for (username, password) in rows:
                db_path = os.path.join(app.root_path, 'db', 'cards_%s.db' % (username))
                users[username] = dict(PASSWORD=password, DATABASE=db_path)
        except sqlite3.Error as er:
            if "no such table: users" in str(er):
                init_user_db()
            else:
                raise
        finally:
            db.close()
    
    return users

def register(username, password):
    error = None
    if username in app.config['USERNAMES']:
        error = 'Username already taken'
    elif len(password) < 6:
        error = 'Password must atleast have a length of 6'
    else:
        db = connect_db(os.path.join(app.root_path, 'db', 'users.db'))
        pwhash = binascii.hexlify(hashlib.pbkdf2_hmac('sha256', bytes(password, 'UTF-8'), bytes(username, 'UTF-8'), 100000)).decode('UTF-8')
        query = '''
          INSERT INTO users
            (username, password)
          VALUES
            (?, ?)
        '''    
        db.execute(query,
                   [username,
                    pwhash
                   ])
        db.commit()
        db.close()
        print("[DEBUG]: User %s was registred" % (username))
        load_configuration()
    return error


def authenticate(username, password):
    error = None
    pwhash = binascii.hexlify(hashlib.pbkdf2_hmac('sha256', bytes(password, 'UTF-8'), bytes(username, 'UTF-8'), 100000)).decode('UTF-8')
    if not username in app.config['USERNAMES']:
        error = 'Invalid username'
    elif pwhash != app.config['USERS'][username]['PASSWORD']:
        error = 'Invalid password'
    else:
        session['session_id'] = str(uuid.uuid4())
        authenticated[session['session_id']] = username
        print("[DEBUG]: User %s logged in with session id %s" % (username, session['session_id']))
        session.permanent = False
    return error


@app.route('/mark_known/<card_id>/<card_type>')
def mark_known(card_id, card_type):
    if not 'session_id' in session or not session['session_id'] in authenticated:
        return redirect(url_for('login'))
    db = get_db()
    db.execute('UPDATE cards SET known = 1 WHERE id = ?', [card_id])
    db.commit()
    flash('Card marked as known.')
    return redirect(url_for(card_type))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'session_id' in session and session['session_id'] in authenticated:
        logout()
    error = None
    if request.method == 'POST':
        error = register(request.form['username'], request.form['password'])
        if error is None:
            return redirect(url_for('initdb'))
    return render_template('register.html', error=error)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'session_id' in session and session['session_id'] in authenticated:
        logout()
    error = None
    if request.method == 'POST':
        error = authenticate(request.form['username'], request.form['password'])
        if error is None:
            return redirect(url_for('cards'))
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    if 'session_id' in session and session['session_id'] in authenticated:
        print("[DEBUG]: User %s logged out" % (authenticated[session['session_id']]))
        authenticated.pop(session['session_id'])
        session.pop('session_id', None)
        flash("You've logged out")
    return redirect(url_for('index'))


def load_configuration():
    users = retrieve_users()
    usernames = users.keys()

    print(users)

    # Load default config and override config from an environment variable
    app.config.update(dict(
        SECRET_KEY='development key',
        USERNAMES=usernames,
        USERS=users
    ))
    app.config.from_envvar('CARDS_SETTINGS', silent=True)

load_configuration()

if __name__ == '__main__':
    app.run(host='0.0.0.0', threaded=True)

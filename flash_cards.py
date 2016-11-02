import os
import sqlite3
import binascii
import hashlib
import uuid
from flask import Flask, request, session, g, redirect, url_for, abort, \
    render_template, flash

app = Flask(__name__)
app.config.from_object(__name__)
authenticated = {}

# Load default config and override config from an environment variable
app.config.update(dict(
    SECRET_KEY='development key',
    USERNAMES=['linus','samuel'],
    USERS=dict(
        linus=dict(
            PASSWORD='60ab74861dbd43ae51eeb7b637774ad566bafb1ed1341c5dfb183bb97bc361a7',
            DATABASE=os.path.join(app.root_path, 'db', 'cards_linus.db')
        ),
        samuel=dict(
            PASSWORD='27ece3f4389a96cff3afd85e2d65a59217b844f41c41521637a68585453c5b4d',
            DATABASE=os.path.join(app.root_path, 'db', 'cards_samuel.db')
        )
    )
))
app.config.from_envvar('CARDS_SETTINGS', silent=True)

def connect_db():
    if not session['session_id'] in authenticated:
        return None
    rv = sqlite3.connect(app.config['USERS'][authenticated[session['session_id']]]['DATABASE'])
    rv.row_factory = sqlite3.Row
    return rv


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


# -----------------------------------------------------------

# Uncomment and use this to initialize database, then comment it
#   You can rerun it to pave the database and start over
@app.route('/initdb')
def initdb():
    init_db()
    flash("Initialized database")
    return redirect(url_for('general'))


@app.route('/')
def index():
    if session.get('logged_in'):
        return redirect(url_for('general'))
    else:
        return redirect(url_for('login'))


@app.route('/cards')
def cards():
    if not session.get('logged_in'):
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
    if not session.get('logged_in'):
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
    if not session.get('logged_in'):
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
    if not session.get('logged_in'):
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
    if not session.get('logged_in'):
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
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    db = get_db()
    db.execute('DELETE FROM cards WHERE id = ?', [card_id])
    db.commit()
    flash('Card deleted.')
    return redirect(url_for('cards'))


@app.route('/general')
@app.route('/general/<card_id>')
def general(card_id=None):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return memorize("general", card_id)


@app.route('/code')
@app.route('/code/<card_id>')
def code(card_id=None):
    if not session.get('logged_in'):
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


@app.route('/mark_known/<card_id>/<card_type>')
def mark_known(card_id, card_type):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    db = get_db()
    db.execute('UPDATE cards SET known = 1 WHERE id = ?', [card_id])
    db.commit()
    flash('Card marked as known.')
    return redirect(url_for(card_type))


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        pwhash = binascii.hexlify(hashlib.pbkdf2_hmac('sha256', bytes(request.form['password'], 'UTF-8'), bytes(username, 'UTF-8'), 100000)).decode('UTF-8')
        if not username in app.config['USERNAMES']:
            error = 'Invalid username'
        elif pwhash != app.config['USERS'][username]['PASSWORD']:
            error = 'Invalid password'
        else:
            session['logged_in'] = True
            session['session_id'] = str(uuid.uuid4())
            authenticated[session['session_id']] = username
            print("[DEBUG]: User %s logged in with session id %s" % (username, session['session_id']))
            session.permanent = False
            return redirect(url_for('cards'))
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    if session['session_id'] in authenticated:
        print("[DEBUG]: User %s logged out" % (authenticated[session['session_id']]))
        authenticated.pop(session['session_id'])
        session.pop('session_id', None)
    session.pop('logged_in', None)
    flash("You've logged out")
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', threaded=True)

''' 
Windows:
set FLASK_APP=oauth.py
flask -m flask run
'''

from flask import (
    abort,
    Flask,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
import json
import logging
import requests
import secrets
import string
import threading
import random
from datetime import datetime, timedelta
from urllib.parse import urlencode
from fuzzywuzzy import fuzz
from db import DB

logging.basicConfig(format = '%(asctime)s - %(levelname)s - %(message)s', 
                    level = logging.DEBUG)

# Client info
with open('config.json', 'r') as f:
    config = json.load(f)
CLIENT_ID = config['client_id']
CLIENT_SECRET = config['client_secret']
SECRET_KEY = config['secret_key']
REDIRECT_URI = 'http://127.0.0.1:5000/callback'

# Spotify API endpoints
AUTH_URL = 'https://accounts.spotify.com/authorize'
TOKEN_URL = 'https://accounts.spotify.com/api/token'
ME_URL = 'https://api.spotify.com/v1/me'
PLAYLISTS_URL = 'https://api.spotify.com/v1/users/{USER_ID}/playlists?limit=50'

# Start Flask up
app = Flask(__name__, static_url_path = '/static')
app.secret_key = SECRET_KEY
# These three configuration parameters are required if the app is going to be served
# from a server which domain name is an ip. Otherwise, cookies will not be stored
# by Chrome.
app.config['SERVER_NAME'] = '127.0.0.1:5000'
app.config['SESSION_COOKIE_NAME'] = '127.0.0.1:5000'
app.config['SESSION_COOKIE_DOMAIN'] = '127.0.0.1:5000'

# Database constants and initialisation (including creating the database table if 
# it doesn't already exist)
DB_FILE = 'db/user_threads.db'
db = DB(DB_FILE, app.logger)
sql_table = '''
CREATE TABLE IF NOT EXISTS user_threads (id integer PRIMARY KEY, username text NOT NULL)
'''
db.run_sql(sql_table)

def _validate_api_call(res):
    '''
    Produces an error message and interrupts the application if the code returned by the API
    call is different from 200.

    Parameters:
        - res: the response object returned by a request call
    '''
    if res.status_code != 200:
        app.logger.error(
            'Failed to connect to connect to Spotify\'s API: %s',
            res.json().get('error', 'No error message returned.'),
        )
        abort(res.status_code)

def _init_playlists():
    '''
    Common code used in multiple functions in which we need to validate some data
    before processing the playlists
    '''
    global processing_threads

    if session.get('thread_id') is None or session['thread_id'] not in processing_threads.keys():
        return redirect(url_for('index'))

    thread_id = session['thread_id']

    if 'tokens' not in session:
        app.logger.error('No tokens in session.')
        abort(400)

    if not thread_id in processing_threads.keys():
        app.logger.error('Wrong thread id.')
        abort(500)

def _init_thread():
    '''
    Initialises and launches a processing thread
    '''
    global processing_threads   

    # Get profile info
    headers = {'Authorization': f"Bearer {session['tokens']['access_token']}"}
    res = requests.get(ME_URL, headers = headers)
    _validate_api_call(res)
    res_data = res.json()
    user_id = res_data['id']

    db = DB(DB_FILE, app.logger)
    select_query = 'SELECT id FROM user_threads WHERE username = "' + user_id + '"'
    rows = db.run_sql(select_query)
    if len(rows) == 0:
        db.run_sql('INSERT INTO user_threads(username) VALUES ("' + user_id + '")')
    rows = db.run_sql(select_query)
    thread_id = rows[0][0]
    processing_threads[thread_id] = ProcessingThread(session['tokens']['access_token'], user_id)
    processing_threads[thread_id].start()
    session['thread_id'] = thread_id

class ProcessingThread(threading.Thread):
    ''' 
    Class to process user's data asynchronously on the background by means of a thread
    '''
    def __init__(self, access_token, user_id):
        self.access_token = access_token
        self.user_id = user_id
        self.progress_api = 0
        self.progress_duplicated = 0
        self.playlists = []
        self.duplicated = []
        self.date_completed = None
        self.running_time = None
        self.kill = False
        super().__init__()

    def _pull_playlists(self):
        '''
        Pulls the complete list of playlists by looking at the first API query response
        '''
        def _read_page(res_data):
            return [res_data['items'][i]['name'] for i in range(len(res_data['items']))]
        headers = {'Authorization': f"Bearer {self.access_token}"}
        res = requests.get(PLAYLISTS_URL.replace('{USER_ID}', self.user_id), headers = headers)
        _validate_api_call(res)
        res_data = res.json()
        self.playlists = _read_page(res_data)
        while res_data['next'] is not None and self.kill == False:
            res = requests.get(res_data['next'], headers = headers)
            _validate_api_call(res)
            res_data = res.json()
            self.playlists.extend(_read_page(res_data))

    def get_len_playlists(self):
        '''
        Get the total number of playlists in the user's collection

        Returns:
            - Number of playlists in the user's collection
        '''
        return len(self.playlists)

    def run(self):
        '''
        Prepares the data to be presented to the user: a) pulls username from access token, b) gets
        user's playlist names, and c) detects duplicated playlists. All this data is stored as 
        internal object properties. 
        '''
        date_started = datetime.now()
        

        self._pull_playlists()
        self.progress_api = 1

        total_size = len(self.playlists) * (len(self.playlists) - 1) / 2.0
        processed = 0
        for i in range(len(self.playlists)):
            if self.kill:
                break
            for j in range(i + 1, len(self.playlists)):
                if self.kill:
                    break
                processed += 1
                self.progress_duplicated = round((processed / total_size) * 100, 2)
                if fuzz.ratio(self.playlists[i], self.playlists[j]) > 90:
                    self.duplicated.append([self.playlists[i], self.playlists[j]])
        if self.kill:
            print('KILLLED')

        self.date_completed = datetime.now()
        self.running_time = str(timedelta(seconds = (self.date_completed - date_started).total_seconds()))
        self.date_completed = self.date_completed.strftime("%d/%m/%Y - %H:%M:%S")

processing_threads = {}

@app.route('/')
def index():
    '''
    Initial endpoint.
    '''
    if session.get('thread_id') is None or session['thread_id'] not in processing_threads.keys():
        return render_template('index.html')
    else:
        return redirect(url_for('playlists'))

@app.route('/<loginout>')
def login(loginout):
    '''
    Login or logout user. Login and logout process are essentially the same. Logout 
    forces re-login to appear, even if their token hasn't expired.
    '''
    # redirect_uri can be guessed, so let's generate
    # a random `state` string to prevent csrf forgery.
    state = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))

    # Request authorization from user
    scope = 'playlist-read-private playlist-read-collaborative'

    if loginout == 'logout':
        payload = {
            'client_id': CLIENT_ID,
            'response_type': 'code',
            'redirect_uri': REDIRECT_URI,
            'state': state,
            'scope': scope,
            'show_dialog': True,
        }
        processing_threads[session['thread_id']].kill = True
        session['thread_id'] = None
    elif loginout == 'login':
        payload = {
            'client_id': CLIENT_ID,
            'response_type': 'code',
            'redirect_uri': REDIRECT_URI,
            'state': state,
            'scope': scope,
        }
    else:
        abort(404)

    res = make_response(redirect(f'{AUTH_URL}/?{urlencode(payload)}'))
    res.set_cookie('spotify_auth_state', state)

    return res

@app.route('/callback')
def callback():
    '''
    Deals with Spotify's answer
    '''
    global processing_threads

    error = request.args.get('error')
    code = request.args.get('code')
    state = request.args.get('state')
    stored_state = request.cookies.get('spotify_auth_state')

    if error == 'access_denied':
        return redirect(url_for('index'))

    # Check state
    if state is None or state != stored_state:
        app.logger.error('Error message: %s', repr(error))
        app.logger.error('State mismatch: %s != %s', stored_state, state)
        abort(400)

    # Request tokens with the code we obtained
    payload = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
    }

    # `auth=(CLIENT_ID, SECRET)` basically wraps an 'Authorization'
    # header with value:
    # b'Basic ' + b64encode((CLIENT_ID + ':' + SECRET).encode())
    res = requests.post(TOKEN_URL, 
                        auth = (CLIENT_ID, CLIENT_SECRET), 
                        data = payload)
    _validate_api_call(res)
    res_data = res.json()

    # Load tokens into session
    session['tokens'] = {
        'access_token': res_data.get('access_token'),
        'refresh_token': res_data.get('refresh_token'),
    }

    if session.get('thread_id') is None or session['thread_id'] not in processing_threads.keys():
        _init_thread()

    return redirect(url_for('playlists'))

@app.route('/refresh')
def refresh():
    '''
    Refresh access token
    '''

    payload = {
        'grant_type': 'refresh_token',
        'refresh_token': session.get('tokens').get('refresh_token'),
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    res = requests.post(TOKEN_URL, 
                        auth = (CLIENT_ID, CLIENT_SECRET), 
                        data = payload, 
                        headers = headers)
    _validate_api_call(res)
    res_data = res.json()

    # Load new token into session
    session['tokens']['access_token'] = res_data.get('access_token')

    return json.dumps(session['tokens'])

@app.route('/reset')
def reset():
    '''
    Kills the existing thread and therefore restarts the duplicates search 
    '''
    global processing_threads

    _init_playlists()

    _init_thread()

    return redirect(url_for('playlists'))

@app.route('/playlists')
def playlists():
    '''
    Pulls user's playlists and displays duplicated playlists
    '''
    global processing_threads

    _init_playlists()

    thread_id = session['thread_id']

    return render_template('playlists.html', 
                           progress_api = processing_threads[thread_id].progress_api,
                           len_playlists = processing_threads[thread_id].get_len_playlists(),
                           progress_duplicated = processing_threads[thread_id].progress_duplicated,
                           data = processing_threads[thread_id].duplicated, 
                           date_completed = processing_threads[thread_id].date_completed,
                           running_time = processing_threads[thread_id].running_time,
                           tokens = session.get('tokens'))
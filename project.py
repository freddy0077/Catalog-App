from flask import Flask, render_template, request, redirect
from flask import jsonify, url_for, flash
from sqlalchemy import create_engine, asc, desc, text
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
import bcrypt
import re
from functools import wraps
from sqlalchemy.sql import func

import urllib
from markupsafe import Markup

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Application"


# Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in login_session:
            flash('Login is required for this action')
            return redirect(url_for('showLogin', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
@app.route('/catalog/')
def showCatalogs():
    sql = text('SELECT name, id, (SELECT O.name FROM [Item] '
               'O WHERE O.category_id = C.id '
               'ORDER BY created_at DESC) AS item '
               'FROM Category C ORDER BY name ASC'
               )
    results = engine.execute(sql)

    categories = session.query(Category).order_by(asc(Category.name))

    return render_template('index.html', categories=categories,
                           results=results)


@app.route('/<category>/items')
@app.route('/catalog/<category>/items')
def showCategory(category):
    categories = session.query(Category).order_by(asc(Category.name))

    category_object = session.query(Category)\
        .filter_by(name=category).one()
    items = session.query(Item)\
        .filter_by(category_id=category_object.id) \
        .order_by(desc(Item.created_at)).all()
    if 'username' not in login_session:
        return render_template('category.html', category=category,
                               categories=categories, items=items,
                               )
    else:
        return render_template('category.html', category=category,
                               categories=categories, items=items,
                               )


@app.route('/catalog/search/', methods=['GET'])
def search():
    item = request.args.get('search', None)
    category_id = request.args.get('category', None)
    categories = session.query(Category).order_by(asc(Category.name))
    items = session.query(Item).filter(Item.name.like("%"+item+"%")) \
        .filter_by(category_id=category_id).all()
    category = session.query(Category).filter_by(id=category_id).first()
    return render_template('search_results.html', items=items,
                           categories=categories, category=category)


@app.route('/item/<category>/<item>')
@app.route('/catalog/<category>/<item>')
def showItem(category, item):
    category_id = session.query(Category).filter_by(name=category).first().id
    itemObject = session.query(Item).filter_by(name=item) \
        .filter_by(category_id=category_id).first()
    return render_template('item.html', item=itemObject)


@app.route('/catalog/add-category/', methods=['GET', 'POST'])
@login_required
def addCategory():
        if request.method == 'POST':
            name = request.form['category_name']
            user_id = login_session['user_id']
            category = Category(user_id=user_id, name=name)
            session.add(category)
            session.commit()
            flash('You have successfully added a new category!')
            return redirect('/catalog')
            # return "<script>function myFunction() {" \
            #        "alert('You have successfully " \
            #        "added a new category. '); " \
            #        "location.href='/catalog'}" \
            #        "</script><body onload='myFunction()''>"


@app.route('/catalog/add-item/')
@app.route('/catalog/add-item/', methods=['GET', 'POST'])
@login_required
def addCategoryItem():
        if request.method == 'POST':
            category_id = request.form['category_id']
            user_id = login_session['user_id']
            category = session.query(Category).filter_by(id=category_id).one()

            newItem = Item(name=request.form['name'],
                           description=request.form['description'],
                           price=request.form['price'],
                           category_id=category_id,
                           user_id=user_id)
            session.add(newItem)
            session.commit()
            flash('New %s Item Successfully Created' % newItem.name)
            return redirect(url_for('showCategory', category=category.name))
        else:
            email = login_session['email']
            picture = login_session['picture']
            categories = session.query(Category).all()
            return render_template('add_item2.html', email=email,
                                   picture=picture, categories=categories)


# @app.route('/catalog/add-item')
@app.route('/catalog/<category>/add-item', methods=['GET', 'POST'])
@login_required
def addItem(category):
    category = session.query(Category).filter_by(name=category).one()
    if login_session['user_id'] != category.user_id:
        flash('You are not authorized to add '
              'items to this category')
        return redirect('/catalog')
    else:
        if request.method == 'POST':
            newItem = Item(name=request.form['name'],
                           description=request.form['description'],
                           price=request.form['price'],
                           category_id=category.id,
                           user_id=category.user_id)
            session.add(newItem)
            session.commit()
            flash('New Menu %s Item Successfully Created' % newItem.name)
            return redirect(url_for('showCategory',
                                    category=category.name))
        else:
            email = login_session['email']
            picture = login_session['picture']
            categories = session.query(Category).all()
            return render_template('add_item.html',
                                   email=email, picture=picture,
                                   categories=categories,
                                   category=category.name)


@app.route('/catalog/<item>/edit/<int:itemid>/', methods=['GET', 'POST'])
@login_required
def editItem(item, itemid):
    # if 'username' not in login_session:
    #     return redirect('/login')
    editedItem = session.query(Item).filter_by(id=itemid).one()
    if login_session['user_id'] != editedItem.user_id:
        flash("You are not authorized to edit item!"
              " Please create your own category in order to edit items.")
        return redirect(url_for('showLogin'))

    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        session.add(editedItem)
        session.commit()
        flash('Item Successfully Edited')
        return redirect(url_for('editItem', item=editedItem.name,
                                itemid=editedItem.id))
    else:
        category_item = session.query(Item).filter_by(id=itemid).one()
        categories = session.query(Category).all()
        return render_template('edit_item.html', category_item=category_item,
                               categories=categories)


@app.route('/catalog/<item>/delete/<itemid>/', methods=['GET', 'POST'])
@login_required
def deleteItem(item, itemid):
    item_to_delete = session.query(Item).filter_by(id=itemid).one()
    category = session.query(Category) \
        .filter_by(id=item_to_delete.category_id).one()

    if login_session['user_id'] != item_to_delete.user_id:
        flash("You are not authorized to delete item!"
              " Please create your own category in order to edit items.")
        return redirect(url_for('showLogin'))
    else:
        if request.method == 'POST':
            session.delete(item_to_delete)
            session.commit()
            flash('Item successfully deleted!')
            return redirect(url_for('showCategory', category=category.name))
        else:
            return render_template('delete_item.html',
                                   category_item=item_to_delete,
                                   item=item, itemid=itemid)


# Create anti-forgery state token
@app.route('/catalog/login', methods=['GET', 'POST'])
def showLogin():
    if request.method == 'POST':
        email = request.form['email']
        if valid_email(email):
            if verify_password(request.form['email'],
                               request.form['password']):
                user = session.query(User).filter_by(email=email).first()
                # flash('Successfully logged in')
                login_session['username'] = user.name
                login_session['email'] = user.email
                login_session['user_id'] = user.id
                login_session['picture'] = ''
                session.add(user)
                session.commit()
                return redirect(url_for('showCatalogs'))
            else:
                email = request.form['email']
                flash('credentials not valid!')
                return render_template('login.html', email=email)
        else:
            return render_template('login.html', email=email,
                                   error_email="email is invalid!")
    else:

        state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                        for x in xrange(32))
        login_session['state'] = state
        return render_template('login.html', STATE=state, user='')


@app.route('/catalog/register', methods=['POST'])
def registerUser():
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']
    user_exists = session.query(User).filter_by(email=email).first()
    params = dict(username=name, email=email)
    params['username'] = name
    params['email'] = email

    have_error = False

    if not valid_username(name):
        params['error_username'] = "That's not a valid username."
        have_error = True

    if not valid_password(password):
        params['error_password'] = "That wasn't a valid password"
        have_error = True

    if not valid_email(email):
        params['error_email'] = "That's not a valid email."
        have_error = True

    if user_exists:
        params['email_exists'] = "email already exists."
        have_error = True

    if have_error:
        return render_template('login.html', **params)

    else:
        user = User(
            name=request.form['name'],
            email=request.form['email'],
            password=bcrypt.hashpw(request.form['password'].encode(),
                                   bcrypt.gensalt())
        )
        login_session['username'] = user.name
        login_session['email'] = user.email
        login_session['user_id'] = user.id
        login_session['picture'] = ''
        session.add(user)
        session.commit()
        return redirect(url_for('showCatalogs'))


@app.route('/catalog/logout', methods=['GET'])
def logOut():
    try:
        del login_session['username']
        del login_session['email']
        del login_session['user_id']
        del login_session['picture']
        del login_session['provider']
        flash('successfully logged out')
        return redirect(url_for('showLogin',))
    except KeyError:
        pass
        return redirect(url_for('showLogin',))


@app.route('/catalog/edit-account', methods=['GET', 'POST'])
@login_required
def editAccount():
    user = session.query(User). \
        filter_by(email=login_session['email']).first()

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone_number = request.form['phone_number']
        user.name = name
        user.email = email
        user.phone_number = phone_number
        flash('successfully updated your account')
        return redirect(url_for('editAccount'))
    else:

        return render_template('edit_account.html', user=user)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token' \
          '?grant_type=fb_exchange_token&' \
          'client_id=%s&client_secret=%s&fb_exchange_token=%s' \
          % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from
        the server token exchange we have to
        split the token first on commas and
        select the first index which gives us the key : value
        for the server access token then we split it on colons
        to pull out the actual token value
        and replace the remaining quotes with nothing so
        that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s' \
          '&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&' \
          'redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;' \
              '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' \
          % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is '
                                            'already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: ' \
              '150px;-webkit-border-radius: 150px;' \
              '-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
        'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# JSON APIs to view Restaurant Information
@app.route('/catalog.json')
def catalogJSON():
    items = session.query(Item).all()
    return jsonify(category=[r.serialize for r in items])


@app.route('/catalog/<int:category_id>/item/JSON')
def categoryItemJSON(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(
        category_id=category_id).all()
    return jsonify(Items=[i.serialize for i in items])


@app.route('/catalog/<int:category_id>/item/<int:item_id>/JSON')
def itemJSON(category_id, item_id):
    Category_Item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(Item=Category_Item.serialize)


@app.route('/catalog/categories/JSON')
def categoriesJSON():
    categories = session.query(Category).all()
    return jsonify(catg=[r.serialize for r in categories])


def verify_password(email, password):
    user = session.query(User).filter_by(email=email).first()
    if user:
        encoded_password = password.encode('utf-8')
        pwhash = bcrypt.hashpw(encoded_password, user.password.encode('utf-8'))
        return user.password == pwhash


# check for valid email
def valid_email(email):
    email_regex = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
    return not email or email_regex.match(email)


def valid_password(password):
    # valid password regular expression
    pass_regex = re.compile(r"^.{3,20}$")
    return password and pass_regex.match(password)


# check for valid username
def valid_username(username):
    username_regex = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and username_regex.match(username)



if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

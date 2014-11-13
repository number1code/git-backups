#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import webapp2
import jinja2
import re
import hmac
import hashlib
import random
import string
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

secret = 'aslkldfjg594858204lskdjfas0dlfkj'

def make_secure_val(val):
    return "%s|%s" % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val #else None gets returned

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(string.letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()#select * from User where name = name
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

class BlogPostDB(db.Model):
    subject = db.StringProperty(required = True)
    # title = db.TextProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

class MainPage(Handler):
    def get(self):
        posts = db.GqlQuery("SELECT * FROM BlogPostDB ORDER BY created DESC limit 10")
        #posts = BlogPostDB.all().order('-creatied')#procedural instead of gql language
        self.render("front2.html", posts=posts)

class NewPostPage(Handler):
    def render_front(self, subject="", content="", error=""):
        self.render("newpost.html", subject=subject, content=content, error=error)

    def get(self):
        self.render_front()

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            a = BlogPostDB(subject=subject, content=content)
            a.put()
            id = a.key().id()
            self.redirect('/%s' % str(id))
        else:
            error = "we need both subject and content"
            self.render_front(subject, content, error)

class EntryHandler(Handler):
    def get(self, post_id):
        post = BlogPostDB.get_by_id (int(post_id), None)
        self.render("newentry.html", subject=post.subject, content=post.content)



USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")


def valid_username(username):
    return USER_RE.match(username)

def valid_password(password):
    return PASSWORD_RE.match(password)

def valid_email(email):
    return  EMAIL_RE.match(email)

class SignupPage(Handler):
    def write_signup(self, error_username = "", name_error="", password_error="", verify_error="", email_error="", username="", email=""):
        self.render("signup.html", error_username=error_username, name_error=name_error, password_error=password_error, verify_error=verify_error, email_error=email_error, username=username, email=email)

    def get(self):
        self.write_signup()

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        name_error = ""
        password_error = ""
        verify_error = ""
        email_error = ""

        flag = True
        if not valid_username(username):
            name_error = "That's not a valid username"
            flag = False
        if not valid_password(password):
            password_error = "That wasn't a valid password"
            flag = False
        if not (password == verify):
            verify_error = "Your passwords didn't match"
            flag = False
        if email and not valid_email(email):
            email_error = "That's not a valid email"
            flag = False

        if flag:
            #make sure the user doesn't already exist
            u = User.by_name(username)
            if u:
                msg = 'That user already exists.'
                self.write_signup(error_username=msg)
            else:
                u = User.register(username, password, email)
                u.put()

                self.login(u)
                self.redirect('/welcome')
            #self.redirect("/welcome?username=" + username)
        else:
            self.write_signup(name_error, password_error, verify_error, email_error, username, email)


class WelcomeHandler(Handler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

    # def write_welcome(self, username=""):
    #     self.render("welcome.html", username=username)
    #
    # def get(self):
    #   self.write_welcome(self.request.get('username'))

class Login(Handler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/signup')


app = webapp2.WSGIApplication([
    ('/', MainPage), ('/newpost', NewPostPage), ('/([0-9]+)', EntryHandler), ('/signup', SignupPage), ('/welcome', WelcomeHandler), ('/login', Login), ('/logout', Logout)
], debug=True)

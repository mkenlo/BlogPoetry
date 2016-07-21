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
import datetime
import hashlib
import re
from google.appengine.ext import ndb
from google.appengine.api import users
from string import letters
import hmac

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)
salt = "hElLo+YoU@aPp&enGine"
secret_cookie = "no$"

# [Form Validation]
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)
# [end Form Validation]

# [Password and Cookie checking security]
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret_cookie, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val
def check_secure_pass(tochecked_val,secure_val):
	hash_passwd = hashlib.md5(salt+tochecked_val).hexdigest()
	return hash_passwd == secure_val
# [ end of Password and Cookie checking security]

# Application handler
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_user_cookie(self,value):
        self.response.headers.add_header('Set-Cookie','user=%s'%make_secure_val(value))

    def logged(self):
        user_cookie = self.request.cookies.get('user')
        if user_cookie and check_secure_val(user_cookie):
            return user_cookie.split(',')[0]



# class model to represent article's author
class Account(ndb.Model):
    username = ndb.StringProperty()
    email_address = ndb.StringProperty()
    passwd = ndb.StringProperty()
    
# class model to represent a blog
class Post(ndb.Model):
    title = ndb.StringProperty(required = True)
    content = ndb.TextProperty(required = True)
    created= ndb.DateTimeProperty(auto_now_add=True)


class Home(Handler):
    def get(self):
        params = dict()
        posts = Post.query().order(-Post.created)
        cookie = self.logged()
        if cookie:
            params['username'] = cookie.split('|')[0]         
            # self.response.out.write(params['username']) 
        if not posts:
            self.render('blog.html', error = "No posts for the moment")
        else:   
            params['posts'] = posts.fetch()
            self.render('blog.html', **params) 
       

class AddPost(Handler):
    def get(self): 
    	cookie = self.logged()       
        if cookie:
            self.render('addpost.html', username=cookie.split('|')[0])
        else:
            self.redirect('/login')   

    def post(self):
        post_title = self.request.get("post-title")
        post_content = self.request.get("content")  
       
        if post_title and post_content:
            new_post = Post(title=post_title, content=post_content)
            key=new_post.put()
            self.redirect('/blog/%s' % key.id())
        else:
            self.render('addpost.html', error= " Title or Content not found")

class SinglePost(Handler):
    def get(self, post_id):
        key = ndb.Key(Post, int(post_id))
        post = key.get()

        if not post:
            self.error(404)
            return
        cookie = self.logged()
        params = dict(post = post)       
        if cookie:
            params['username'] = cookie.split('|')[0]
                
        self.render('singlepost.html', **params)

class SignUp(Handler):
    def get(self):
        self.render('signup.html')

    def post(self):
        have_error = False
        username = self.request.get("username")
        email_address =  self.request.get("email_address")
        passwd = self.request.get("password")
        confirm_passwd = self.request.get("password_confirm")       
        params = dict(user_name = username, email_address = email_address)
        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True
        if not valid_password(passwd):
            params['error_password'] = "That wasn't a valid password."
            have_error = True       
        elif passwd != confirm_passwd:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True
        if not valid_email(email_address):
            params['error_email'] = "That's not a valid email."
            have_error = True 
        if Account.query(Account.username == username).fetch():   
            params['used_username'] = "This username is already used"
            have_error = True
        if have_error:
            self.render('signup.html', **params)        
        else:
            hash_passwd = hashlib.md5(salt+passwd).hexdigest()
            new_account = Account (username = username, 
                email_address=email_address, 
                passwd=hash_passwd,
                id= username)
            
            new_account.put()
            self.redirect('/login')
           

class Login(Handler):
    def get(self):      
        if self.logged():
            self.redirect('/blog')
        else:
            self.render('login.html')
    def post(self):
        user = Account.query(Account.username == self.request.get('username')).fetch()
        # self.response.out.write(check_secure_pass(self.request.get('password'),user[0].passwd))
        if user and check_secure_pass(self.request.get('password'),user[0].passwd):
            self.set_user_cookie(str(user[0].username))         
            self.redirect('/blog')
        else:
            self.redirect('/signup')
           

class Logout(Handler):
    def get(self):
        if self.logged():
            self.response.delete_cookie('user')
            self.redirect('/login')
        else:
        	self.redirect('/blog')

app = webapp2.WSGIApplication([
    ('/', Home), ('/blog',Home),
    ('/signup',SignUp), ('/login', Login),
    ('/blog/add', AddPost), ('/blog/([0-9]+)',SinglePost),('/logout',Logout)

], debug=True)

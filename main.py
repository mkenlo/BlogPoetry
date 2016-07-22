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
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)
salt = "hElLo+YoU@aPp&enGine"
secret_cookie = "no$"

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')



class BlogSecurity:
    """ This class contains all methods to check the security if each link and cookie of the website
        It contains methods to validate the username, the password and the email entered while a registration.
        It als o contains methods to ensure a valid cookie user
    """
    @staticmethod
    def valid_username(username):
        return username and USER_RE.match(username)
    @staticmethod    
    def valid_password(password):
        return password and PASS_RE.match(password)
    @staticmethod
    def valid_email(email):
        return not email or EMAIL_RE.match(email)
    @staticmethod    
    def make_secure_val(val):
        return '%s|%s' % (val, hmac.new(secret_cookie, val).hexdigest())
    @staticmethod    
    def check_secure_val(secure_val):
        val = secure_val.split('|')[0]
        if secure_val == BlogSecurity.make_secure_val(val):
            return val
    @staticmethod
    def check_secure_pass(tochecked_val,secure_val):
        hash_passwd = hashlib.md5(salt+tochecked_val).hexdigest()
        return hash_passwd == secure_val
    @staticmethod
    def logged_user(cookie):
        if cookie:
           user = cookie.split('|')[0]
           return user
        return False

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
        self.response.headers.add_header('Set-Cookie','user=%s'%BlogSecurity.make_secure_val(value))

    def logged(self):
        user_cookie = self.request.cookies.get('user')
        if user_cookie and BlogSecurity.check_secure_val(user_cookie):
            return user_cookie
    def current_user(self):
        return User.get_by_id(BlogSecurity.logged_user(self.logged()))        


# class model to represent article's author
class User(ndb.Model):
    """ This class model represent article's author: each user has a unique username, email and password"""
    username = ndb.StringProperty(required = True)
    email_address = ndb.StringProperty()
    passwd = ndb.StringProperty(required = True)
    
# class model to represent a blog
class Post(ndb.Model):
    """ This class model represent a post or article:
    each post has a title, a content, creation date, a user id who posted it and its number of like
    """
    title = ndb.StringProperty(required = True)
    content = ndb.TextProperty(required = True)
    created= ndb.DateTimeProperty(auto_now_add=True)
    author = ndb.KeyProperty(kind = 'User')
    likes = ndb.IntegerProperty()

class Comments(ndb.Model):
    """ This class model represent comments on post: a comment is describe by a content, the post_id 
    and the user id who comment the post"""
    post_id = ndb.KeyProperty(kind = 'Post')
    comment = ndb.TextProperty(required = True)
    author = ndb.KeyProperty(kind = 'User')

class Home(Handler):
    def get(self):
        params = dict()
        posts = Post.query().order(-Post.created)
        cookie = self.logged()
        # self.response.out.write(cookie)
        if cookie:
            params['username'] = cookie.split('|')[0]         
            # self.response.out.write(params['username']) 
        if not posts:
            self.render('blog.html', error = "No posts for the moment")
        else:   
            params['posts'] = posts.fetch(12)
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
            current_user = self.current_user()
            new_post.author = current_user.key
            new_post.likes = 0
            
            key=new_post.put()
            self.redirect('/blog/%s' % key.id())
        else:
            self.render('addpost.html', error= " Title or Content not found")

class EditPost(Handler):
    def get(self, post_id):
        key = ndb.Key(Post, int(post_id))
        post = key.get()
        if not post :
            self.error(404)
            return
        #self.response.out.write(post)
        if post.author != self.current_user().key:
            redirect('/blog/%s' % key.id())
        cookie = self.logged()
        params = dict(post = post)       
        if cookie:
            params['username'] = cookie.split('|')[0]

        self.render('editpost.html', **params)
    def post(self, post_id):
        post_title = self.request.get("post-title")
        post_content = self.request.get("content")  
        key = ndb.Key(Post, int(post_id))
        post = key.get() 
        if post and post_title and post_content:
            post.title=post_title
            post.content = post_content                    
            post.put()
            self.redirect('/blog/%s' % key.id())
        else:
            self.render('editpost.html', error= " Title or Content not found")

class DeletePost(Handler):
    def get(self, post_id):
        if not self.logged():
            self.redirect('/login')
            return
        key = ndb.Key(Post, int(post_id))
        post = key.get()
        if post.author != self.current_user().key:
            self.redirect('/blog/%s' % key.id())
            return
        if post:
            post.key.delete()
        self.redirect("/blog")
        

class CommentPost(Handler):
    def get(self, post_id):
        if not self.logged():
            self.redirect('/login')
            return

        key = ndb.Key(Post, int(post_id))
        post = key.get()        
        if not post:
            self.error(404)
            return
        if post.author != self.current_user().key:
            params = dict(post = post, username = self.current_user().key.id())                    
            self.render('commentpost.html', **params)
        else:
            self.redirect('/login') 
    def post(self, post_id):
        comment = self.request.get('content')
        key = ndb.Key(Post, int(post_id))
        post = key.get()
        self.response.out.write(post)
        self.response.out.write(comment)
        if post and comment:
            new_comment = Comments(post_id = key, comment = comment, author = self.current_user().key)
            new_comment.put()            
        self.redirect('/blog/%s'% key.id())
        return
        
class LikePost(Handler):
    def get(self, post_id):
        if not self.logged():
            self.redirect('/login')
            return 
        key = ndb.Key(Post, int(post_id))
        post = key.get()
        if post and (post.author != self.current_user().key):
            post.likes = post.likes+1
            post.put()
        self.redirect('/blog')
        return

class SinglePost(Handler):
    def get(self, post_id):
        key = ndb.Key(Post, int(post_id))
        post = key.get()

        if not post:
            self.error(404)
            return
        cookie = self.logged()
        params = dict(post = post)
        
        post_comments = Comments.query(Comments.post_id == key).fetch(10)
        if post_comments:
            params['post_comments'] =post_comments
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
        if not BlogSecurity.valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True
        if not BlogSecurity.valid_password(passwd):
            params['error_password'] = "That wasn't a valid password."
            have_error = True       
        elif passwd != confirm_passwd:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True
        if not BlogSecurity.valid_email(email_address):
            params['error_email'] = "That's not a valid email."
            have_error = True 
        if User.query(User.username == username).fetch():   
            params['used_username'] = "This username is already used"
            have_error = True
        if have_error:
            self.render('signup.html', **params)        
        else:
            hash_passwd = hashlib.md5(salt+passwd).hexdigest()
            new_User = User (username = username, 
                email_address=email_address, 
                passwd=hash_passwd,
                id= username)
            
            new_User.put()
            self.redirect('/login')
           

class Login(Handler):
    def get(self):      
        if self.logged():
            self.redirect('/blog')
        else:
            self.render('login.html')
    def post(self):
        user = User.query(User.username == self.request.get('username')).fetch()
        
        if user and BlogSecurity.check_secure_pass(self.request.get('password'),user[0].passwd):
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
    ('/', Home), 
    ('/blog',Home),
    ('/signup',SignUp),
    ('/login', Login),
    ('/logout',Logout),
    ('/blog/([0-9]+)',SinglePost),
    ('/blog/add', AddPost),        
    ('/blog/edit/([0-9]+)',EditPost),
    ('/blog/like/([0-9]+)',LikePost),
    ('/blog/comment/([0-9]+)',CommentPost),
    ('/blog/delete/([0-9]+)', DeletePost)

], debug=True)

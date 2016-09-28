#coding:utf8
from gevent.wsgi import WSGIServer
from app import app
http_server = WSGIServer(('',8088),app)
http_server.serve_forever()
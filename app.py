
#coding:utf8
from flask import Flask
from flask import request
from  qqwry_query  import QQWry


app = Flask(__name__)

@app.route('/')
def index():
        ip = request.remote_addr
        qqwry_q = QQWry('qqwry.dat')
        a , d = qqwry_q.query(ip)
        return request.remote_addr+'<br/>'+a+' '+d

if __name__ == "__main__":
        app.run(host='0.0.0.0')
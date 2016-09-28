
#coding:utf8
from flask import Flask,jsonify,request
from  qqwry_query  import QQWry

app = Flask(__name__)

@app.route('/')
def index():
        ip = request.remote_addr
        if request.args.get('ip'):
            ip = request.args.get('ip')
        qqwry_q = QQWry('qqwry.dat')
        a , d = qqwry_q.query(ip)

        return ip + '<br/>' + a.decode('utf8') + ' ' + d.decode('utf8')

@app.route('/json/')
def json():
        ip = request.remote_addr
        if request.args.get('ip'):
            ip = request.args.get('ip')
        qqwry_q = QQWry('qqwry.dat')
        a , d = qqwry_q.query(ip)
        data = {
            'ip':ip,
            'area':a,
            'netname':d
        }
        return jsonify(data)

if __name__ == "__main__":
        app.run(host='0.0.0.0')
#!/usr/bin/env python
# coding: UTF-8

# 解析 QQWry 库


import os
import sys
import socket
import codecs
import mmap
from struct import pack, unpack


def decode_str(old):
    '''专门对纯真的gbk编码字符串解压

    返回 utf8 字符串
    '''
    try:
        return unicode(old,'gbk').encode('utf-8')
    except:
        # TODO: hack
        # 当字符串解码失败，并且最一个字节值为'\x96',则去掉它，再解析
        if old[-1] == '\x96':
            try:
                return unicode(old[:-1],'gbk').encode('utf-8') + '?'
            except:
                pass

        return 'Invalid'


class QQWry(object):

    def __init__(self, path):
        self.path = path
        self.db = None
        self.open_db()
        self.idx_start, self.idx_end = self._read_idx()
        # IP索引总数
        self.total = (self.idx_end - self.idx_start) / 7 + 1

    def open_db(self):
        if not self.db:
            self.db = open(self.path, 'rb')
            self.db = mmap.mmap(self.db.fileno(), 0, access = 1)
        return self.db

    def _read_idx(self):
        '''读取数据库中IP索引起始和结束偏移值

        '''

        self.db.seek(0)
        start = unpack('I', self.db.read(4))[0]
        end = unpack('I', self.db.read(4))[0]

        return start, end

    def version(self):
        '''返回纯真IP库的版本信息

        格式如 "纯真网络2014年8月5日IP数据"
        '''

        ip_end_offset = self.read_offset(self.idx_end + 4)
        a_raw, b_raw = self.read_record(ip_end_offset+4)

        return decode_str(a_raw + b_raw)

    def read_ip(self, off, seek=True):
        '''读取ip值（4字节整数值）

        返回IP值
        '''

        if seek:
            self.db.seek(off)

        buf = self.db.read(4)
        return unpack('I', buf)[0]

    def read_offset(self, off, seek=True):
        '''读取３字节的偏移量值

        返回偏移量的整数值
        '''
        if seek:
            self.db.seek(off)

        buf = self.db.read(3)
        return unpack('I', buf+'\0')[0]

    def read_string(self, offset):
        '''读取原始字符串（以"\0"结束）

        返回元组：字符串
        '''

        if offset == 0:
            return 'N/A1'

        flag = self.get_flag(offset)

        if flag == 0:
            # TODO: 出错
            return 'N/A2'

        elif flag == 2:
            # 0x02 表示该处信息还是需要重定向
            offset = self.read_offset(offset+1)
            return self.read_string(offset)

        self.db.seek(offset)

        raw_string  = ''
        while True:
            x = self.db.read(1)
            if x == '\0':
                break
            raw_string += x

        return raw_string

    def get_flag(self, offset):
        '''读取偏移处的1字节整数值

        QQWry地址信息字符串的第一个字节值可能会是一个标志位，
        这是一个通用的函数．
        '''
        self.db.seek(offset)
        c = self.db.read(1)
        if not c:
            return 0
        return ord(c)

    def read_record(self, offset):

        self.db.seek(offset)

        # 读取 flag
        flag = ord(self.db.read(1))

        if flag == 1:
            # 0x01 表示记录区记录（国家，地区）信息都重定向
            # 注意：一次重定向后记录还有可能是一个重定向(其flag=0x02)

            buf = self.db.read(3)
            a_offset = unpack('I', buf+'\0')[0]

            a_raw = self.read_string(a_offset)

            # TODO: hack
            # 判断新记录的flag是否为0x02，如果是，则表明：
            # - 国家信息重定向另外地址
            # - 地区信息为新记录起始地址偏移4字节
            a_flag = self.get_flag(a_offset)
            if a_flag == 2:
                b_raw = self.read_string(a_offset+4)
            else:
                b_raw = self.read_string(a_offset+len(a_raw)+1)

        elif flag == 2:
            # 0x02 表示仅国家记录重定向
            # 地区信息偏移4字节

            buf = self.db.read(3)
            a_offset = unpack('I', buf+'\0')[0]

            a_raw = self.read_string(a_offset)
            b_raw = self.read_string(offset+4)

        else:
            # 正常的信息记录
            a_raw = self.read_string(offset)
            b_raw = self.read_string(offset+len(a_raw)+1)

        return a_raw, b_raw

    def output(self, output_file='ip.txt'):
        '''输出所有IP信息到文件

        '''

        fp = codecs.open(output_file, 'w', 'utf8')

        idx = self.idx_start
        while idx <= self.idx_end:

            ip_int = self.read_ip(idx)
            ip_start = socket.inet_ntoa(pack('!I', ip_int))

            ip_end_offset = self.read_offset(idx + 4)

            ip_int = self.read_ip(ip_end_offset)
            ip_end = socket.inet_ntoa(pack('!I', ip_int))

            a_raw, b_raw = self.read_record(ip_end_offset+4)

            a_info = decode_str(a_raw)
            b_info = decode_str(b_raw)

            fp.write(u'%15s\t%15s\t%s,%s\n' %(
                ip_start, ip_end,
                a_info.decode('utf8'), b_info.decode('utf8')))

            # 步进7字节：4字节的起始IP值 + 3字节的结束IP偏移值
            idx += 7

        fp.close()

    def find(self, ip, l, r):
        '''使用二分法查找网络字节编码的IP地址的索引记录

        '''

        if r - l <= 1:
            return l

        m = (l + r) / 2
        offset = self.idx_start + m * 7

        new_ip = self.read_ip(offset)

        if ip < new_ip:
            return self.find(ip, l, m)
        else:
            return self.find(ip, m, r)

    def query(self, ip):
        '''查询IP信息

        '''

        # 使用网络字节编码IP地址
        ip = unpack('!I', socket.inet_aton(ip))[0]
        # 使用 self.find 函数查找ip的索引偏移
        i = self.find(ip, 0, self.total - 1)
        # 得到索引记录
        o = self.idx_start + i * 7
        # 索引记录格式是： 前4字节IP信息+3字节指向IP记录信息的偏移量
        # 这里就是使用后3字节作为偏移量得到其常规表示（QQWry.Dat用字符串表示值）
        o2 = self.read_offset(o + 4)
        # IP记录偏移值+4可以丢弃前4字节的IP地址信息。
        (c, a) = self.read_record(o2 + 4)
        return (decode_str(c), decode_str(a))

    def __del__(self):
        if self.db:
            self.db.close()


def update_db(dbpath):
    '''更新 QQWry IP数据库

    参考：https://github.com/lilydjwg/winterpy/blob/master/pylib/QQWry.py
    '''

    import subprocess
    import zlib

    copywrite_url = 'http://update.cz88.net/ip/copywrite.rar'
    data_url = 'http://update.cz88.net/ip/qqwry.rar'

    def decipher_data(key, data):
        h = bytearray()
        for b in data[:0x200]:
            b = ord(b)
            key *= 0x805
            key += 1
            key &= 0xff
            h.append(key ^ b)
        return bytes(h) + data[0x200:]

    def unpack_meta(data):
        # http://microcai.org/2014/05/11/qqwry_dat_download.html
        (sign, version, _1, size, _, key, text,
         link) = unpack('<4sIIIII128s128s', data)
        sign = sign.decode('gb18030')
        text = text.rstrip(b'\x00').decode('gb18030')
        link = link.rstrip(b'\x00').decode('gb18030')
        del data
        return locals()

    p = subprocess.Popen(['wget', copywrite_url])
    p.wait()
    d = open('copywrite.rar', 'rb').read()
    info = unpack_meta(d)

    p = subprocess.Popen(['wget', data_url])
    p.wait()
    d = open('qqwry.rar', 'rb').read()
    d = decipher_data(info['key'], d)
    d = zlib.decompress(d)

    open(dbpath, 'w').write(d)

    os.unlink('copywrite.rar')
    os.unlink('qqwry.rar')


def parse_cmd_args():
    '''处理命令行选项

    '''

    import argparse

    parser = argparse.ArgumentParser(
        prog='qqwry',
        description='qqwry is an IP address lookup process, for QQWry(cz88.net).')

    group = parser.add_mutually_exclusive_group()

    group.add_argument("-q", dest='query', action="store",
                       nargs='+', # 可指定多个IP
                       help="lookup ip.")

    group.add_argument("--query-file", action="store",
                       dest='query_file',
                       nargs='+', # 可指定多个IP
                       help="lookup ip from files")

    group.add_argument("--dump", action="store_true",
                       help="dump all ip information to a file.")

    parser.add_argument("--update-db", action="store_true", default=False,
                        help="update qqwry.dat")

    parser.add_argument("--quiet", action="store_true", default=False,
                        help="quiet mode.")

    parser.add_argument('-f', '--dbpath',
                        action="store",
                        default='qqwry.dat',
                        help='the path of qqwry.dat')

    parser.add_argument('-o', '--output',
                        action="store",
                        default='ip.txt',
                        help='save output of ip info to a file')


    args = parser.parse_args()
    if not (args.query or args.query_file or args.dump):
        parser.print_help()
        sys.exit(0)

    return args


def main():

    args = parse_cmd_args()

    ## 是否需要更新

    # 1. 指定更新
    if args.update_db:
        update_db(args.dbpath)

    # 2. 没有发现 qqwry.dat
    if not os.path.exists(args.dbpath):
        update_db(args.dbpath)

    qqwry = QQWry(args.dbpath)
    if not args.quiet:
        print qqwry.version()
        print 'index total: ', qqwry.total
        print

    if args.query:
        for ip in args.query:
            c, a = qqwry.query(ip)
            print '%15s %s%s' % (ip, c, a)

    elif args.query_file:
        for p in args.query_file:
            with open(p, 'r') as f:
                while True:
                    ip = f.readline().strip()
                    if not ip:
                        break

                    c, a = qqwry.query(ip)
                    print '%15s %s%s' % (ip, c, a)

    elif args.dump:
        print 'dumping to %s ...' % args.output
        qqwry.output()


if __name__ == '__main__':

    main()

##
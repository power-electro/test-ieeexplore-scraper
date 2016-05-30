#!/usr/bin/python
#----------------------------------------------------------------------
#
# Author:      soheil sabzevari
#
# Copyright:   (c) 2015 by Elasa Co. LTD
# Licence:     BSD style
#
#
#----------------------------------------------------------------------
# from __future__ import with_statement
# from google.appengine.api import files
import os, re, errno, sys, time
import urllib
import urllib2, urlparse
from urlparse import urlparse as urlparse2
from BeautifulSoup import BeautifulSoup
import cookielib
import mimetypes

import random
import mechanize
import md5, hashlib


print "Content-type: text/html\n"
print "this is running"


def import_mod(**kwargs):
    # import_mod(from_module='sss',from_module2='s')
    from_module_name1 = kwargs['from_module']
    try:
        kwargs['from_module2']
        from_module_name2 = kwargs['from_module2']
    except:
        from_module_name2 = ''

    try:
        kwargs['dir_location']
        CurrentDir = os.path.dirname(os.path.realpath(__file__))
        s = CurrentDir.replace('\\', '/') + kwargs['dir_location']
        sys.path.insert(0, s)
    except:
        pass
    if from_module_name1 in sys.modules:
        print "@@@@@@@@@@@@@@ module already exist  for " + from_module_name1 + ' is \n: @@@@@@@@@@@@@@\n\n'
        if from_module_name2 == '':
            mod = sys.modules[from_module_name1]
        else:
            mod1 = sys.modules[from_module_name1]
            mod = getattr(mod1, from_module_name2)
            print "@@@@@@@@@@@@@@ module already exist  for " + from_module_name1 + '.' + from_module_name2 + ' is \n: @@@@@@@@@@@@@@\n\n'
    else:
        print "@@@@@@@@@@@@@@ module inserting for " + from_module_name1 + "  \n: @@@@@@@@@@@@@@\n\n"
        if from_module_name2 == '':
            mod = __import__(from_module_name1)
        else:
            mod1 = __import__(from_module_name1)
            mod = getattr(mod1, from_module_name2)
            # mod = getattr(mod1,from_module_name2)
            pass
            print's'
            # mod=mod1[from_module_name2]
    return mod

    # return urlparse.urljoin('file:', urllib.pathname2url(path))


class MozillaCacher(object):
    """A dictionary like object, that can cache results on a storage device."""

    def __init__(self, cachedir='.cache'):
        self.cachedir = cachedir
        if not os.path.isdir(cachedir):
            os.mkdir(cachedir)

    def name2fname(self, name):
        return os.path.join(self.cachedir, name)

    def __getitem__(self, name):
        if not isinstance(name, str):
            raise TypeError()
        fname = self.name2fname(name)
        if os.path.isfile(fname):
            return file(fname, 'rb').read()
        else:
            raise IndexError()

    def __setitem__(self, name, value):
        if not isinstance(name, str):
            raise TypeError()
        fname = self.name2fname(name)
        if os.path.isfile(fname):
            os.unlink(fname)
        f = file(fname, 'wb+')
        try:
            f.write(value)
        finally:
            f.close()

    def __delitem__(self, name):
        if not isinstance(name, str):
            raise TypeError()
        fname = self.name2fname(name)
        if os.path.isfile(fname):
            os.unlink(fname)

    def __iter__(self):
        raise NotImplementedError()

    def has_key(self, name):
        return os.path.isfile(self.name2fname(name))


class HTTPNoRedirector(urllib2.HTTPRedirectHandler):
    """This is a custom http redirect handler that FORBIDS redirection."""

    def http_error_302(self, req, fp, code, msg, headers):
        e = urllib2.HTTPError(req.get_full_url(), code, msg, headers, fp)
        if e.code in (301, 302):
            if 'location' in headers:
                newurl = headers.getheaders('location')[0]
            elif 'uri' in headers:
                newurl = headers.getheaders('uri')[0]
            e.newurl = newurl
        raise e


def get_content_type(filename):
    return mimetypes.guess_type(filename)[0] or 'application/octet-stream'


def encode_multipart_formdata(fields, files):
    """
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return (content_type, body) ready for httplib.HTTP instance
    """
    BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
    CRLF = '\r\n'
    L = []
    for (key, value) in fields:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    for (key, filename, value) in files:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
        L.append('Content-Type: %s' % get_content_type(filename))
        L.append('')
        L.append(value)
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body


class MozillaEmulator(object):
    def __init__(self, cacher={}, trycount=0, debug=False, **kwargs):
        """Create a new MozillaEmulator object.

        @param cacher: A dictionary like object, that can cache search results on a storage device.
            You can use a simple dictionary here, but it is not recommended.
            You can also put None here to disable caching completely.
        @param trycount: The download() method will retry the operation if it fails. You can specify -1 for infinite retrying.
                A value of 0 means no retrying. A value of 1 means one retry. etc."""

        if kwargs['cookies']:
            self.cookie3 = kwargs['cookies']
        else:
            self.cookie3 = ''
        self.cacher = cacher
        if self.cookie3 != '':
            self.cookies = cookielib.MozillaCookieJar(self.cookie3)
        else:
            self.cookies = cookielib.MozillaCookieJar()
        # self.cookies = cookielib.CookieJar()
        self.debug = debug
        self.trycount = trycount

    def _hash(self, data):
        h = md5.new()
        h.update(data)
        return h.hexdigest()

    def build_opener(self, url, proxy=[], User_Pass=[], postdata=None, extraheaders={}, forbid_redirect=False):

        txheaders = {
            'Accept': 'text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5',
            'Accept-Language': 'en,hu;q=0.8,en-us;q=0.5,hu-hu;q=0.3',
            #            'Accept-Encoding': 'gzip, deflate',
            'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.7',
            #            'Keep-Alive': '300',
            #            'Connection': 'keep-alive',
            #            'Cache-Control': 'max-age=0',
        }
        for key, value in extraheaders.iteritems():
            txheaders[key] = value
        req = urllib2.Request(url, postdata, txheaders)
        self.cookies.add_cookie_header(req)
        if forbid_redirect:
            redirector = HTTPNoRedirector()
        else:
            redirector = urllib2.HTTPRedirectHandler()

        if proxy != [] and (not re.findall("None", proxy)) and proxy != '':
            if User_Pass != [] and User_Pass != '':
                proxies = {"http": "http://" + User_Pass + "@" + proxy}
            else:
                proxies = {"http": "http://%s" % proxy}
            proxy_support = urllib2.ProxyHandler(proxies)
            # opener = urllib2.build_opener(proxy_support, urllib2.HTTPHandler(debuglevel=1))
        else:
            proxy_support = urllib2.ProxyHandler()
            # opener = urllib2.build_opener(proxy_support, urllib2.HTTPHandler(debuglevel=1))
            # url=link.absolute_url
            # headers={'User-agent' : 'Mozilla/5.0'}

        http_handler = urllib2.HTTPHandler(debuglevel=self.debug)
        https_handler = urllib2.HTTPSHandler(debuglevel=self.debug)

        # default_classes = [ProxyHandler, UnknownHandler, HTTPHandler,
        #                    HTTPDefaultErrorHandler, HTTPRedirectHandler,
        #                    FTPHandler, FileHandler, HTTPErrorProcessor]


        u = urllib2.build_opener(proxy_support, http_handler, https_handler, urllib2.HTTPCookieProcessor(self.cookies),
                                 redirector)
        urllib2.install_opener(u)

        u.addheaders = [
            ('User-Agent', 'Mozilla/5.0 (Windows; U; Windows NT 5.1; hu-HU; rv:1.7.8) Gecko/20050511 Firefox/1.0.4')]
        if not postdata is None:
            req.add_data(postdata)

        if self.cookie3 == '':
            fo = os.getcwd().replace('\\', '/')
            # pathname = os.path.join("cookies", cookie3)
            site = urlparse2(url).hostname
            if not os.path.isdir(fo + "/cookies/" + site): os.mkdir(fo + "/cookies/" + site)
            chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            self.cookie3 = fo + "/cookies/" + site + '/' + ''.join([random.choice(chars) for x in range(5)]) + ".txt"
        self.cookies.save(self.cookie3)
        return (req, u, self.cookie3)

    def download(self, url, proxy=[], User_Pass=[], postdata=None, extraheaders={}, forbid_redirect=False,
                 trycount=None, fd=None, onprogress=None, only_head=False):
        """Download an URL with GET or POST methods.

        @param proxy: set the proxy setting.
        @param User_Pass: user_pass for proxy.
        @param postdata: It can be a string that will be POST-ed to the URL.
            When None is given, the method will be GET instead.
        @param extraheaders: You can add/modify HTTP headers with a dict here.
        @param forbid_redirect: Set this flag if you do not want to handle
            HTTP 301 and 302 redirects.
        @param trycount: Specify the maximum number of retries here.
            0 means no retry on error. Using -1 means infinite retring.
            None means the default value (that is self.trycount).
        @param fd: You can pass a file descriptor here. In this case,
            the data will be written into the file. Please note that
            when you save the raw data into a file then it won't be cached.
        @param onprogress: A function that has two parameters:
            the size of the resource and the downloaded size. This will be
            called for each 1KB chunk. (If the HTTP header does not contain
            the content-length field, then the size parameter will be zero!)
        @param only_head: Create the openerdirector and return it. In other
            words, this will not retrieve any content except HTTP headers.

        @return: The raw HTML page data, unless fd was specified. When fd
            was given, the return value is undefined.
        """
        if trycount is None:
            trycount = self.trycount
        cnt = 0
        while True:
            try:
                key = self._hash(url)
                if (self.cacher is None) or (not self.cacher.has_key(key)):
                    req, u, cookie3 = self.build_opener(url, proxy, User_Pass, postdata, extraheaders, forbid_redirect)
                    openerdirector = u.open(req)
                    if self.debug:
                        print req.get_method(), url
                        print openerdirector.code, openerdirector.msg
                        print openerdirector.headers
                    self.cookies.extract_cookies(openerdirector, req)
                    if only_head:
                        return openerdirector
                    if openerdirector.headers.has_key('content-length'):
                        length = long(openerdirector.headers['content-length'])
                    else:
                        length = 0
                    dlength = 0
                    # piece_size = 4096 # 4 KiB
                    piece_size = 1024 * 1024 # 1MB
                    if fd:
                        while True:
                            data = openerdirector.read(piece_size)
                            dlength += len(data)
                            fd.write(data)
                            if onprogress:
                                onprogress(length, dlength)
                            if not data:
                                break
                    else:
                        data = ''
                        while True:
                            newdata = openerdirector.read(piece_size)
                            dlength += len(newdata)
                            data += newdata
                            if onprogress:
                                onprogress(length, dlength)
                            if not newdata:
                                break
                                #data = openerdirector.read()
                        if not (self.cacher is None):
                            self.cacher[key] = data
                else:
                    data = self.cacher[key]
                    #try:
                #    d2= GzipFile(fileobj=cStringIO.StringIO(data)).read()
                #    data = d2
                #except IOError:
                #    pass
                self.cookies.save(self.cookie3)
                return data, cookie3
            except urllib2.URLError:
                er = urllib2.URLError
                cnt += 1
                if (trycount > -1) and (trycount < cnt):
                    raise
                    # Retry :-)
                if self.debug:
                    print "MozillaEmulator: urllib2.URLError, retryting ", cnt


    def post_multipart(self, url, fields, files, pr=[], Up=[], forbid_redirect=True, ):
        """Post fields and files to an http host as multipart/form-data.
        fields is a sequence of (name, value) elements for regular form fields.
        files is a sequence of (name, filename, value) elements for data to be uploaded as files
        Return the server's response page.
        """
        content_type, post_data = encode_multipart_formdata(fields, files)
        result = self.download(url, pr, Up, post_data, {
            'Content-Type': content_type,
            'Content-Length': str(len(post_data))
        }, forbid_redirect=forbid_redirect
        )
        return result


class MECAHNIZM(object):
    def __init__(self, proxy='', User_Pass='', **kwargs):
        global PDF_Dir, Watermarked_PDF_Files_Dir
        if kwargs['cookies']:
            self.cookie3 = kwargs['cookies']
        else:
            self.cookie3 = ''
        if kwargs['url']:
            self.url = kwargs['url']
        else:
            self.url = ''

        self.proxy = proxy
        self.User_Pass = User_Pass
        self.br = self.BROWSER()

    def progressbar(self):
        pass
        # from clint.textui import progress
        # r = requests.get(url, stream=True)
        # with open(path, 'wb') as f:
        #     total_length = int(r.headers.get('content-length'))
        #     for chunk in progress.bar(r.iter_content(chunk_size=1024), expected_size=(total_length/1024) + 1):
        #         if chunk:
        #             f.write(chunk)
        #             f.flush()

    def BROWSER(self, cookie3=''):
        """
        :param url:
        """
        # global br, cj, r, proxy, User_Pass


        br = mechanize.Browser()
        # print br

        # Cookie Jar
        # fo=os.getcwd()+"\\cookies\\"
        # try :
        #     os.mkdir(fo)
        # except:
        #     pass
        # os.chdir(fo)
        # folder=sys.path.insert(0,'/cookies')

        # os.chdir(..)


        # Browser options
        br.set_handle_equiv(True)
        br.set_handle_gzip(True)
        br.set_handle_referer(True)    # no allow everything to be written to
        br.set_handle_robots(False)   # no robots
        br.set_handle_refresh(True)  # can sometimes hang without this
        br.set_handle_redirect(True)

        # Follows refresh 0 but not hangs on refresh > 0
        br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=3)

        # Want debugging messages?
        #br.set_debug_http(True)
        br.set_debug_redirects(True)
        #br.set_debug_responses(True)

        # # User-Agent (this is cheating, ok?)
        # br.addheaders = [('User-Agent', 'Mozilla/5.0 (Linux; U; Android 2.3.4; en-us; T-Mobile myTouch 3G Slide Build/GRI40) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1'),
        #                  ('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'),
        #                  ('Accept-Language', 'en-gb,en;q=0.5'),
        #                  ('Accept-Encoding', 'gzip,deflate'),
        #                  ('Accept-Charset', 'ISO-8859-1,utf-8;q=0.7,*;q=0.7'),
        #                  ('Keep-Alive', '115'),
        #                  ('Connection', 'keep-alive'),
        #                  ('Cache-Control', 'max-age=0'),
        #                  ('Referer', 'http://yahoo.com')]

        # User-Agent (this is cheating, ok?)
        # br.addheaders = [('User-agent',
        #               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')]

        br.addheaders = [
            ('User-agent',
             'Mozilla/5.0 (Windows NT 6.1; rv:23.0) Gecko/20100101 Firefox/23.0'),
            ('Accept',
             'text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5;application/json;text/javascript;*/*'),
            ('Accept-Language', 'en,hu;q=0.8,en-us;q=0.5,hu-hu;q=0.3'),
            ('Accept-Encoding', 'gzip, deflate'),
            ('Accept-Charset', 'ISO-8859-1,utf-8;q=0.7,*;q=0.7'),
            ('Keep-Alive', '300'),
            ('Connection', 'keep-alive'),
            ('Cache-Control', 'max-age=0'),
            ('Referer', self.url),
            ('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8'),
            ('X-Requested-With', 'XMLHttpRequest')
        ]
        # # If the protected site didn't receive the authentication data you would
        # # end up with a 410 error in your face
        # br.add_password('http://safe-site.domain', 'username', 'password')
        # br.open('http://safe-site.domain')

        # Open some site, let's pick a random one, the first that pops in mind:
        # Proxy and user/password
        #proxy = "61.233.25.166:80"

        # proxy = "202.202.0.163:3128"
        # proxy=self.proxy
        # Proxy
        # dd=re.findall('None:None', proxy)
        if self.proxy != [] and self.proxy != '' and not (re.findall('None', self.proxy)):
            br.proxies = br.set_proxies({"http": self.proxy})
            # br.proxies=br.set_proxies( proxy)

        if self.User_Pass != [] and self.User_Pass != '' and not (re.findall('None:None', self.User_Pass)):
            br.add_proxy_password(self.User_Pass.split(":")[0], self.User_Pass.split(":")[1])

        # if  r!={}:
        # rr = br.open(url)

        # c= cookielib.Cookie(version=0, name='PON', value="xxx.xxx.xxx.111", expires=365, port=None, port_specified=False, domain='xxxx', domain_specified=True, domain_initial_dot=False, path='/', path_specified=True, secure=True, discard=False, comment=None, comment_url=None, rest={'HttpOnly': False}, rfc2109=False)
        # cj.set_cookie(c0)
        if self.cookie3 == '':
            CurrentDir = os.path.dirname(os.path.realpath(__file__)).replace('\\', '/')
            fo = os.path.abspath(os.path.join(CurrentDir, '../..')).replace('\\', '/')
            # pathname = os.path.join("cookies", cookie3)
            site = urlparse2(self.url).hostname
            if not os.path.isdir(fo + "/cookies/" + site): os.mkdir(fo + "/cookies/" + site)
            chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            self.cookie3 = fo + "/cookies/" + site + '/' + ''.join([random.choice(chars) for x in range(5)]) + ".txt"
            self.cj = cookielib.LWPCookieJar()
            opener = mechanize.build_opener(mechanize.HTTPCookieProcessor(self.cj))
            br.set_cookiejar(self.cj)
            self.cj.save(self.cookie3)
        else:
            self.cj = cookielib.LWPCookieJar()
            # self.cj.revert(self.cookie3)
            opener = mechanize.build_opener(mechanize.HTTPCookieProcessor(self.cj))
            br.set_cookiejar(self.cj)
            # self.cj.load(self.cookie3)
            # self.cj.save( self.cookie3, ignore_discard=True, ignore_expires=True)

            # cookiefile=open(self.cookie3,'r')
            # s0=cookiefile.readlines()
            # # print s0
            # for i in range(0,len(s0)):
            #     if re.findall(':',s0[i]):
            #         s2=s0[i].split(':')[1].replace('\n','')
            #         print s2
            #         br.set_cookie(s2)





        # self.cj.save( self.cookie3)

        return br


    # Proxy password
    # br.add_proxy_password("joe", "password")
    # self.dl_acm = "http://dl.acm.org/citation.cfm?id=99977.100000&coll=DL&dl=ACM"


    def speed_download(self, pdf_url, piece_size=1024 * 1024,timeout=1111):
        # br2=self.br

        cookiefile = open(self.cookie3, 'r')
        s0 = cookiefile.readlines()
        # print s0
        # for i in range(0,len(s0)):
        #     if re.findall(':',s0[i]):
        #         s2=s0[i].split(':')[1].replace('\n','')
        #         print s2
        #         self.br.set_cookie(s2)
        # socket=import_mod(from_module='socket')
        # socket.setdefaulttimeout(300)
        # openerdirector = self.br.open(pdf_url,timeout=timeout)
        openerdirector = self.br.open(pdf_url)
        try:
            if (openerdirector._headers.dict['content-type']) == 'application/pdf':
                length = long(openerdirector._headers.dict['content-length'])
                ok = True
            else:
                length = 0
        except:
            length = 0
        dlength = 0
        # piece_size = 4096 # 4 KiB
        # piece_size =1024*1024 # 1MB
        data = ''

        while True:
            newdata = openerdirector.read(piece_size)
            dlength += len(newdata)
            data += newdata
            if length != 0:
                status = r"%10d [%3.2f%%]" % (dlength, dlength * 100. / length)
                status = status + chr(8) * (len(status) + 1)
                print status
                # pdf_path=PDF_File().file_save(data, "PDF_Files\\", localName.filename)
            # if onprogress:
            #     onprogress(length,dlength)
            if not newdata:
                self.cj.save(self.cookie3)
                break
        if  data != []:
           [links, title] = link_tag_find(data, pdf_url)
           if links !=[] and links !='':
               data2=self.br_folow_link(self.br,self.cookie3)
               responce = {
                'html': data2,
                'links':links,
                'title':title,
                'file':data2
                }
               return responce, self.cookie3 #,pdf_path
           else:
               return [], self.cookie3
    def br_folow_link(self,br,cookies):

        for link1 in self.br.links(url_regex=".pdf"):


                # http://www.rfc-editor.org/rfc/rfc2606.txt
                # if re.findall(links11, link1.url):
                    print(link1)
                    # Link(base_url='http://www.example.com/', url='http://www.rfc-editor.org/rfc/rfc2606.txt', text='RFC 2606', tag='a', attrs=[('href', 'http://www.rfc-editor.org/rfc/rfc2606.txt')])
                    print(link1.url)
                    print('match found')
                    # match found
                    break

        br2=self.br
        try:

            self.br.follow_link(link1)   # link still holds the last value it had in the loop
            # print(br.geturl())
            pdf_link=self.br.geturl()
        except:
            for link2 in br2.links(url_regex=".pdf"):


                # http://www.rfc-editor.org/rfc/rfc2606.txt
                # if re.findall(links11, link1.url):
                    print(link2)
                    # Link(base_url='http://www.example.com/', url='http://www.rfc-editor.org/rfc/rfc2606.txt', text='RFC 2606', tag='a', attrs=[('href', 'http://www.rfc-editor.org/rfc/rfc2606.txt')])
                    print(link2.url)
                    print('match found')
                    # match found
                    break
            br2.follow_link(link2)   # link still holds the last value it had in the loop
            # print(br.geturl())
            pdf_link=br2.geturl()

        if pdf_link:
                self.br.set_cookiejar(self.cj)
                self.cj.save(cookies, ignore_discard=True, ignore_expires=True)
                # return html2, self.cookies, pdf_link, title, 0, self.log_out

                localName = LINK(PDF_Dir=PDF_Dir, Watermarked_PDF_Files_Dir=Watermarked_PDF_Files_Dir).filename2(pdf_link)
                try:
                    f1 = self.br.retrieve(pdf_link, localName.pdf_Folder_filename)
                except:
                    f1 =br2.retrieve(pdf_link, localName.pdf_Folder_filename)

                return f1[0]
        else:
            return []
    def download_pdf_br0(self, pdf_url1):
        class pdf_url():
            abs = 1
            if not ("pdf_url1.absolute_url" is locals()):
                absolute_url = str(pdf_url1)
            else:
                pdf_url = str(pdf_url1)

            def __init__(self):
                self.absolute_url = 2
                if not ("pdf_url1.absolute_url" is locals()):
                    self.absolute_url = str(pdf_url1)
                else:
                    pdf_url = str(pdf_url1)

        # pdf_url = pdf_url1
        # pdf_url.='test'.split()
        # pdf_url2=str(pdf_url1)
        # if not ("pdf_url1.absolute_url" is locals()):
        #     pdf_url.absolute_url = pdf_url2.split()
        # else:
        #     pdf_url = pdf_url1
        if pdf_url.absolute_url.endswith(".pdf") or pdf_url.absolute_url.endswith(".zip"):
            if pdf_url.absolute_url:
                # localName1 = basename(urlsplit(pdf_url.absolute_url)[2])
                localName = LINK(PDF_Dir=PDF_Dir, Watermarked_PDF_Files_Dir=Watermarked_PDF_Files_Dir).filename(
                    pdf_url.absolute_url)
                # pathname = os.path.join("PDF_Files", localName.filename)
                # s=get_full_url(pdf_url)
                # req = self.br.click_link(pdf_url.absolute_url)
                # html = self.br.open(req).read()

                f1 = self.br.retrieve(pdf_url.absolute_url, localName.pdf_Folder_filename)

        else:
            localName = LINK(PDF_Dir=PDF_Dir, Watermarked_PDF_Files_Dir=Watermarked_PDF_Files_Dir).filename(
                pdf_url.absolute_url)
            f1 = self.br.retrieve(pdf_url.absolute_url, localName.pdf_Folder_filename)
            # f1 = self.br.retrieve(pdf_url, localName.pdf_Folder_filename)

        if f1:
            self.cj.save(self.cookie3)

        return f1[0], self.cookie3 #,pdf_path



        # return os.getcwd()+PDF_File.pdf_Folder_filename,os.getcwd()+PDF_File.W_pdf_Folder_filename
    def download_pdf_br(self, pdf_url1):
        class pdf_url():
            abs = 1
            if not ("pdf_url1.absolute_url" is locals()):
                absolute_url = str(pdf_url1)
            else:
                pdf_url = str(pdf_url1)

            def __init__(self):
                self.absolute_url = 2
                if not ("pdf_url1.absolute_url" is locals()):
                    self.absolute_url = str(pdf_url1)
                else:
                    pdf_url = str(pdf_url1)

        # pdf_url = pdf_url1
        # pdf_url.='test'.split()
        # pdf_url2=str(pdf_url1)
        # if not ("pdf_url1.absolute_url" is locals()):
        #     pdf_url.absolute_url = pdf_url2.split()
        # else:
        #     pdf_url = pdf_url1
        try:
          if pdf_url.absolute_url.endswith(".pdf") or pdf_url.absolute_url.endswith(".zip"):
            if pdf_url.absolute_url:
                # localName1 = basename(urlsplit(pdf_url.absolute_url)[2])
                localName = LINK(PDF_Dir=PDF_Dir, Watermarked_PDF_Files_Dir=Watermarked_PDF_Files_Dir).filename(
                    pdf_url.absolute_url)
                # pathname = os.path.join("PDF_Files", localName.filename)
                # s=get_full_url(pdf_url)
                # req = self.br.click_link(pdf_url.absolute_url)
                # html = self.br.open(req).read()

                f1 = self.br.retrieve(pdf_url.absolute_url, localName.pdf_Folder_filename)

          else:
            localName = LINK(PDF_Dir=PDF_Dir, Watermarked_PDF_Files_Dir=Watermarked_PDF_Files_Dir).filename(
                pdf_url.absolute_url)
            f1 = self.br.retrieve(pdf_url.absolute_url, localName.pdf_Folder_filename)
            # f1 = self.br.retrieve(pdf_url, localName.pdf_Folder_filename)
        except:
            if pdf_url1.endswith(".pdf") or pdf_url1.endswith(".zip"):
              if pdf_url:
                # localName1 = basename(urlsplit(pdf_url.absolute_url)[2])
                localName = LINK(PDF_Dir=PDF_Dir, Watermarked_PDF_Files_Dir=Watermarked_PDF_Files_Dir).filename2(
                    pdf_url1)
                # pathname = os.path.join("PDF_Files", localName.filename)
                # s=get_full_url(pdf_url)
                # req = self.br.click_link(pdf_url.absolute_url)
                # html = self.br.open(req).read()

                f1 = self.br.retrieve(pdf_url1, localName.pdf_Folder_filename)

            else:
                localName = LINK(PDF_Dir=PDF_Dir, Watermarked_PDF_Files_Dir=Watermarked_PDF_Files_Dir).filename2(
                pdf_url1)
                f1 = self.br.retrieve(pdf_url1, localName.pdf_Folder_filename)
            # f1 = self.br.retrieve(pdf_url, localName.pdf_Folder_filename)
        if f1:
            self.cj.save(self.cookie3)

        return f1[0], self.cookie3 #,pdf_path



        # return os.getcwd()+PDF_File.pdf_Folder_filename,os.getcwd()+PDF_File.W_pdf_Folder_filename

class web(object):
    def __init__(self, url=''):
        self.url = url

    def download_mechanism(self, url='', proxy='', user_pass='', location='PDF_Files/', **kwargs):
        """

        :param url:
        """
        if kwargs['cookies']:
            cookies = kwargs['cookies']
        else:
            cookies = ''
        if proxy == '' or proxy == []:
            import proxy_checker3_all_function

            fo = os.getcwd().replace('\\', '/')
            pr_h, proxy_h, user_pass_h = proxy_checker3_all_function.make_returning_proxy("configs//sites_proxy//", url)
            os.chdir(fo)
        else:
            pr_h = []
            user_pass_h = []
            pr_h.append(proxy)
            user_pass_h.append(user_pass)
            try:
                i = user_pass_h.index("")
                del user_pass_h[i]
            except:
                print 'there is no empty lsit in user_password list'
            try:
                i = pr_h.index("")
                del pr_h[i]
            except:
                print 'there is no empty lsit in proxy list'

        # pr_h=['222.66.115.233:80 ', '202.202.0.163:3128 ', '151.236.14.48:80']

        pdf_dw_li = pdf_dw_Wr_li = []
        frontpage = []
        don_flg = -1
        if pr_h != []:
            i = -1
            for j in range(i + 1, len(pr_h)):
                if don_flg != 1:
                    # debug = True
                    # cash = None
                    # dl = MozillaEmulator(cash,0,debug)
                    # dl = MozillaEmulator(cash, 0)
                    try:
                        if 'user_pass_h[j]' is locals():
                            # frontpage,cookies=MECAHNIZM( proxy='', User_Pass='').speed_download(pdf_url,piece_size=1024*1024)
                            frontpage, cookies = MECAHNIZM(pr_h[j], user_pass_h[j], cookies=cookies,
                                                           url=url).speed_download(url)
                            # frontpage,cookies = MECAHNIZM(pr_h[j],user_pass_h[j],cookies=cookies,url=url).download_pdf_br(url)
                            pr = pr_h[j]
                            upss = user_pass_h[j]
                        else:
                            # frontpage,cookies = MECAHNIZM(pr_h[j],cookies=cookies,url=url).download_pdf_br(url)
                            frontpage, cookies = MECAHNIZM(pr_h[j], cookies=cookies, url=url).speed_download(url)
                            pr = pr_h[j]
                            upss = ''
                    except:
                        print "we cant dowload beacuse of invalid tag or invalid proxy line 620" + "\n"
                    if frontpage != []:
                        print "file downloaded "
                        don_flg = 1
                        # pr = pr_h[j]
                        # upss = user_pass_h[j]
                        break
                else:
                    print "we could not download file with  proxy:" + pr_h[j]
            if don_flg != 1:
                print "we are unable to download your file Now!!" + '\n'
                frontpage = []
                pr = ''
                upss = ''
                cookies = ''
        else:
            print "we are unable to download your file Now!! Becaouse proxy is empty" + '\n'
        return frontpage, pr, upss, cookies


    def download_mechanism_link(self, url='', proxy='', user_pass='', location='PDF_Files/', **kwargs):
        """

        :param url:
        """
        try:# kwargs['cookies']:
            cookies = kwargs['cookies']
        except:
            cookies = ''
        try:
            if kwargs['piece_size']:
                piece_size = kwargs['piece_size']
            else:
                piece_size = 1024 * 20
        except:
            piece_size = 1024 * 20
        try:
            url_ref=kwargs['url_reffrence']
        except:
            url_ref=url
        if proxy == '' or proxy == []:
            import proxy_checker3_all_function

            site = urlparse2(url).hostname
            fo = os.getcwd().replace('\\', '/')
            pr_h, proxy_h, user_pass_h = proxy_checker3_all_function.make_returning_proxy(
                "configs//sites_proxy//" + site + '//', url)
            os.chdir(fo)
        else:
            pr_h = []
            user_pass_h = []
            pr_h.append(proxy)
            user_pass_h.append(user_pass)
            try:
                i = user_pass_h.index("")
                del user_pass_h[i]
            except:
                print 'there is no empty lsit in user_password list'
            try:
                i = pr_h.index("")
                del pr_h[i]
            except:
                print 'there is no empty lsit in proxy list'

        # pr_h=['222.66.115.233:80 ', '202.202.0.163:3128 ', '151.236.14.48:80']

        pdf_dw_li = pdf_dw_Wr_li = []
        frontpage = []
        don_flg = -1
        if pr_h != []:
            i = -1
            for j in range(i + 1, len(pr_h)):
                if don_flg != 1:
                    # debug = True
                    # cash = None
                    # dl = MozillaEmulator(cash,0,debug)
                    # dl = MozillaEmulator(cash, 0)
                    try:
                        if 'user_pass_h[j]' is locals():
                            # frontpage,cookies=MECHANIZM( proxy='', User_Pass='').speed_download(pdf_url,piece_size=1024*1024)
                            # frontpage, cookies = MECAHNIZM(pr_h[j], user_pass_h[j], cookies=cookies,url=url).speed_download(url, piece_size)
                            frontpage,cookies = MECAHNIZM(pr_h[j],user_pass_h[j],cookies=cookies,url=url).download_pdf_br(url,piece_size)
                            pr = pr_h[j]
                            upss = user_pass_h[j]
                        else:
                            frontpage,cookies = MECAHNIZM(pr_h[j],cookies=cookies,url=url_ref).download_pdf_br(url)
                            # frontpage, cookies = MECAHNIZM(pr_h[j], cookies=cookies, url=url_ref).speed_download(url,piece_size)
                            pr = pr_h[j]
                            upss = ''
                    except:
                        try:
                            pass# frontpage=self.twill_download( url, cookies)
                        except:
                            print "we cant dowload beacuse of invalid tag or invalid proxy line 620  Proxy:" + pr_h[j]+"\n"
                    if frontpage != []:
                        print "file downloaded "
                        don_flg = 1
                        # pr = pr_h[j]
                        # upss = user_pass_h[j]
                        break
                else:
                    print "we could not download file with  proxy:" + pr_h[j]
            if don_flg != 1:
                print "we are unable to download your file Now!!" + '\n'
                frontpage = []
                pr = ''
                upss = ''
                cookies = ''
        else:
            print "we are unable to download your file Now!! Becaouse proxy is empty" + '\n'
        return frontpage, pr, upss, cookies


    def download_bash_curl(self, url='', proxy='', user_pass='', location='PDF_Files/', **kwargs):
        """

        :param url:
        """
        if kwargs['cookies']:
            cookies = kwargs['cookies']
        else:
            cookies = ''
        if proxy == '' or proxy == []:
            import proxy_checker3_all_function

            fo = os.getcwd().replace('\\', '/')
            pr_h, proxy_h, user_pass_h = proxy_checker3_all_function.make_returning_proxy("configs//sites_proxy//", url)
            os.chdir(fo)
        else:
            pr_h = []
            user_pass_h = []
            pr_h.append(proxy)
            user_pass_h.append(user_pass)
            # try:
            #     i = user_pass_h.index("")
            #     del user_pass_h[i]
            # except:
            #     print 'there is no empty lsit in user_password list'
            try:
                i = pr_h.index("")
                del pr_h[i]
            except:
                pass
                # print 'there is no empty list in proxy list'

        # pr_h=['222.66.115.233:80 ', '202.202.0.163:3128 ', '151.236.14.48:80']

        pdf_dw_li = pdf_dw_Wr_li = []
        frontpage = []
        don_flg = -1
        if pr_h != []:
            i = -1
            for j in range(i + 1, len(pr_h)):
                if don_flg != 1:
                    debug = True
                    cash = None
                    # dl = MozillaEmulator(cash,0,debug)
                    dl = MozillaEmulator(cash, 0, cookies=cookies)
                    try:
                        if cookies != '':
                            st = 'curl  -v --cookie-jar' + cookies + ' -A "Mozilla/5.0 (Windows NT 6.0; rv:30.0) Gecko/20100101 Firefox/27.0"'
                        if user_pass_h[j] != '':

                            #http://stackoverflow.com/questions/14437864/save-result-from-system-command-to-a-variable-using-subprocess
                            st = st + '--proxy http://' + user_pass_h[j] + '@' + pr_h[j] + ' -L ' + url
                            # frontpage,cookies = dl.download(url, pr_h[j], user_pass_h[j])
                            pr = pr_h[j]
                            upss = user_pass_h[j]
                        else:
                            # frontpage,cookies = dl.download(url, pr_h[j])
                            st = st + '--proxy http://' + pr_h[j] + ' -L ' + url
                            pr = pr_h[j]
                            upss = ''
                            #http://stackoverflow.com/questions/14437864/save-result-from-system-command-to-a-variable-using-subprocess
                        import subprocess

                        awk_sort = subprocess.Popen([st], stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
                        awk_sort.wait()
                        output = awk_sort.communicate()[0]
                        print output.rstrip()
                        frontpage = output.rstrip()



                    except:
                        print "we cant download because of invalid tag or invalid proxy line 620" + "\n"

                    if frontpage != []:
                        if len(user_pass_h[j]) != 0:
                            print "file downloaded with " + str(pr_h[j]) + '@' + str(user_pass_h[j])
                        else:
                            print "file downloaded with " + str(pr_h[j])
                        don_flg = 1
                        # pr = pr_h[j]
                        # upss = user_pass_h[j]
                        break
                else:
                    print "we could not download file with  proxy:" + pr_h[j]
            if don_flg != 1:
                print "we are unable to download your file Now!!" + '\n'
                frontpage = []
                pr = ''
                upss = ''
                # cookies=''


        else:
            print "we are unable to download your file Now!! Beacouse proxy is empty" + '\n'

        return frontpage, pr, upss, cookies


    def download(self, url='', proxy='', user_pass='', location='PDF_Files/', **kwargs):
        """

        :param url:
        """
        if kwargs['cookies']:
            cookies = kwargs['cookies']
        else:
            cookies = ''
        if proxy == '' or proxy == []:
            import proxy_checker3_all_function

            fo = os.getcwd().replace('\\', '/')
            pr_h, proxy_h, user_pass_h = proxy_checker3_all_function.make_returning_proxy("configs//sites_proxy//", url)
            os.chdir(fo)
        else:
            pr_h = []
            user_pass_h = []
            pr_h.append(proxy)
            user_pass_h.append(user_pass)
            # try:
            #     i = user_pass_h.index("")
            #     del user_pass_h[i]
            # except:
            #     print 'there is no empty lsit in user_password list'
            try:
                i = pr_h.index("")
                del pr_h[i]
            except:
                pass
                # print 'there is no empty list in proxy list'

        # pr_h=['222.66.115.233:80 ', '202.202.0.163:3128 ', '151.236.14.48:80']

        pdf_dw_li = pdf_dw_Wr_li = []
        frontpage = []
        don_flg = -1
        if pr_h != []:
            i = -1
            for j in range(i + 1, len(pr_h)):
                if don_flg != 1:
                    debug = True
                    cash = None
                    # dl = MozillaEmulator(cash,0,debug)
                    dl = MozillaEmulator(cash, 0, cookies=cookies)
                    try:
                        if user_pass_h[j] != '':

                            frontpage, cookies = dl.download(url, pr_h[j], user_pass_h[j])
                            pr = pr_h[j]
                            upss = user_pass_h[j]
                        else:
                            frontpage, cookies = dl.download(url, pr_h[j])
                            pr = pr_h[j]
                            upss = ''



                    except:
                        print "we cant download because of invalid tag or invalid proxy line 620" + "\n"

                    if frontpage != []:
                        if len(user_pass_h[j]) != 0:
                            print "file downloaded with " + str(pr_h[j]) + '@' + str(user_pass_h[j])
                        else:
                            print "file downloaded with " + str(pr_h[j])
                        don_flg = 1
                        # pr = pr_h[j]
                        # upss = user_pass_h[j]
                        break
                else:
                    print "we could not download file with  proxy:" + pr_h[j]
            if don_flg != 1:
                print "we are unable to download your file Now!!" + '\n'
                frontpage = []
                pr = ''
                upss = ''
                # cookies=''


        else:
            print "we are unable to download your file Now!! Beacouse proxy is empty" + '\n'

        return frontpage, pr, upss, cookies


    def twill_download(self, url, cookies):
        # self.url="%(ezproxy_host)s"%form_data
        # self.database_link="%(database_link)s"%form_data
        # self.username="%(user)s"%form_data
        # self.password="%(pass)s"%form_data
        # self.user_tag="%(user_tag)s"%form_data
        # self.pass_tag="%(pass_tag)s"%form_data
        # self.Form_id="%(Form_id)s"%form_data
        # self.submit_tag_name="%(submit_tag_name)s"%form_data
        # self.submit_tag_value="%(submit_tag_value)s"%form_data
        # self.Form_Type="%(Form_Type)s"%form_data
        # self.log_done="%(Log_test)s"%form_data
        link = url;
        # lg = url['log_out'];
        # url_logout = lg['log_out'];
        # ez_link = lg['ez_link']
        # twil__headers = lg['headers']
        try:
            link = lg['pdf_link']
            # site = urlparse2(link.absolute_url).hostname
        except:
            pass
            # site = urlparse2(link).hostname





        # self.a.config("readonly_controls_writeable", 1)
        # self.b = self.a.get_browser()
        # self.b.set_agent_string("Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.14) Gecko/20080404 Firefox/2.0.0.14")
        # self.b.clear_cookies()
        twill = import_mod(from_module='twill')

        # t_com = twill.commands
        # t_com.reset_browser
        # t_com.reset_output
        t_com = twill.commands

        ## get the default browser
        t_brw = t_com.get_browser()
        try:
            t_brw.set_agent_string(
                "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.14) Gecko/20080404 Firefox/2.0.0.14")

            t_com.add_extra_header('User-agent',
                                   'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')
            t_com.add_extra_header('Accept',
                                   'text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5;application/json;text/javascript;*/*')
            t_com.add_extra_header('Accept-Language', 'en,hu;q=0.8,en-us;q=0.5,hu-hu;q=0.3')
            t_com.add_extra_header('Accept-Encoding', 'gzip, deflate')
            t_com.add_extra_header('Accept-Charset', 'ISO-8859-1,utf-8;q=0.7,*;q=0.7')
            t_com.add_extra_header('Keep-Alive', '300')
            t_com.add_extra_header('Connection', 'keep-alive')
            t_com.add_extra_header('Cache-Control', 'max-age=0')
            # t_com.add_extra_header('Referer', ez_link)
            t_com.add_extra_header('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8')
            t_com.add_extra_header('X-Requested-With', 'XMLHttpRequest')
        except:
            t_com.add_extra_header('User-agent',
                                   'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')
            t_com.add_extra_header('Accept',
                                   "text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5;application/json;text/javascript;*/*")
            t_com.add_extra_header('Accept-Language', 'en,hu;q=0.8,en-us;q=0.5,hu-hu;q=0.3')
            t_com.add_extra_header('Accept-Encoding', 'gzip, deflate')
            t_com.add_extra_header('Accept-Charset', 'ISO-8859-1,utf-8;q=0.7,*;q=0.7')
            t_com.add_extra_header('Keep-Alive', '300')
            t_com.add_extra_header('Connection', 'keep-alive')
            t_com.add_extra_header('Cache-Control', 'max-age=0')
            # t_com.add_extra_header('Referer', ez_link)
            t_com.add_extra_header('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8')
            t_com.add_extra_header('X-Requested-With', 'XMLHttpRequest')


            # t_brw.set_agent_string(twil__headers)

        # cookies=cookies.replace('/','\\')
        try:
            t_brw.load_cookies(cookies)
        except:pass
        # socket=import_mod(from_module='socket')
        # socket.setdefaulttimeout(300)
        ## open the url
        # url = 'http://google.com'
        # t_brw.find_link(link)
        # t_brw.go(link)
        print '@@@@@@@@@@@@@ link download by twill is @@@@@@@@@@@@'
        print link
        print '@@@@@@@@@@@@@ link download by twill is @@@@@@@@@@@@'
        try:
            s = link.absolute_url
            t_brw.follow_link(link)
        except:
            t_brw.go(link)
            # class link_n(object):
            #     def __init__(self):
            #         self.absolute_url = link
            #         self.base_url = ez_link
            #         self.url=ez_link
            #     def url(self):
            #         return self
            # link=link_n.url
        # t_brw.follow_link(link)
        html0 = t_brw.result.page

        print '@@@@@@@@@@@@@ html0 download by twill is @@@@@@@@@@@@'
        print html0[:20]
        print '@@@@@@@@@@@@@ html0 download by twill is @@@@@@@@@@@@'
        # time.sleep(10)




        link2 = t_brw.result.url
        link2 = link.absolute_url
        if not (html0[:4] == '%PDF') or html0 == []:
            t_brw.go(link2)
            html, cookies = MECAHNIZM('', '', cookies=cookies, url=link2).speed_download(link2)
            # html3,pr,upss,cookies=web().download_mechanism_link(link,'',cookies=cookies)
            if not (html[:4] == '%PDF') or html == []:
                t_brw.save_cookies(cookies)
                t_brw = t_com.get_browser()
                t_brw.set_agent_string(
                    "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.14) Gecko/20080404 Firefox/2.0.0.14")
                t_brw.load_cookies(cookies)
                # socket=import_mod(from_module='socket')
                # socket.setdefaulttimeout(300)
                html3, pr, upss, cookies = web().download_mechanism_link(link, '', cookies=cookies)
                t_brw.go(link2)
                html = t_brw.result.page

                print '@@@@@@@@@@@@@ html download by twill is @@@@@@@@@@@@'
                print html
                print '@@@@@@@@@@@@@ html download by twill is @@@@@@@@@@@@'
                # time.sleep(10)
        else:
            html = html0
        # t_brw.go(url_logout)
        os.remove(cookies)
        return html




def twil_find_pdf_link(link):
    site = urlparse2(link).hostname
    # site2=site.replace('.','_')
    fo = os.getcwd().replace('\\', '/')
    CurrentDir = os.path.dirname(os.path.realpath(__file__)).replace('\\', '/')
    Parent_Dir = os.path.abspath(os.path.join(CurrentDir, '../')).replace('\\', '/')
    os.chdir(Parent_Dir)
    tw = twill(site_list_form='sites_proxy/' + site + '/site_list_form.txt')
    form = tw.find_form()
    for k in range(0, len(form)):
        # METHOD = "%(METODE)s" % form[k]
        # if True:
        try:
            if "%(METODE)s" % form[k] == '2':
                [html, cookies, links, title, times, log_out] = tw.login_to_site(link, form[k], [], [])

            elif "%(METODE)s" % form[k] == '1' or "%(METODE)s" % form[
                k] == '1+d' or  "%(METODE)s" % form[
                k] == '1+d+d': #direct find link or direct find link and download
                [html, cookies, links, title, times, log_out] = tw.twill_find_link(link, form[k])
            elif "%(METODE)s" % form[k] == '3':
                [html, cookies, links, title, times, log_out] = tw.twill_find_link(link, form[k])
        # else:
        except:
            os.remove(cookies)
            html=[];cookies='';links=[]; title=''; times=0; log_out=[]

        if links != [] and  (html !=[] and html !=''):
            break
    os.chdir(fo)
    return html, cookies, links, title, form[k], times, log_out


class twill:
    def __init__(self, **kwargs):

        # import socket
        # if kwargs['url']:self.url=kwargs['url']
        if kwargs['site_list_form']: self.site_list_form = kwargs['site_list_form']
        # if kwargs['url_to_ez_file']:self.url_to_ez_file=kwargs['url_to_ez_file']
        # socket=import_mod(from_module='socket')
        # socket.setdefaulttimeout(100)


    def find_form(self):
        sa = open(self.site_list_form, 'r')
        listform = sa.readlines()
        # time.sleep(10)
        sa.close()
        k = -1
        form_data = {}
        # for line in listform:
        #     print '&&&&&&&&'
        #     print line+'\n'
        #     print '&&&&&&&&'
        for line in listform:
            if not re.findall('#', line) and line != '\n':
                k = k + 1
                form_data[k] = self.usr_tag(line.replace('\n', ''))
        return form_data

        # self.url=url

    def find_ez_base_url(self, link):
        form = self.find_form()
        for k in range(0, len(form)):
            self.twill_download(self, link, form[k])
            #     sa=open(self.site_list_form,'r')

    #     listform=sa.readlines()
    #     sa.close()
    #     host= urlparse2(self.url).hostname
    #     k=-1
    #     for line in listform:
    #         if line.find(host)!=-1:
    #             k=k+1
    #             form_data[k]=self.usr_tag(line)
    #             # break
    #     return form_data





    def usr_tag(self, pip):
        z = '--'
        try:
            s = pip.split('USER:' + z)[1].split(":")[0]
            proxy_info = {
                'ezproxy_host': pip.split('USER:' + z)[0].replace(' ', ''),
                'METODE': pip.split('METODE:' + z)[1].split(z)[0],
                'Link_part': pip.split('Link_part:' + z)[1].split(z)[0],
                'user': pip.split('USER:' + z)[1].split(":")[0],
                'pass': pip.split('USER:' + z)[1].split(z)[0].split(":")[1],
                'user_tag': pip.split('Form_Tag:' + z)[1].split(":")[0],
                'pass_tag': pip.split('Form_Tag:' + z)[1].split(z)[0].split(":")[1],
                'submit_tag_name': pip.split('Submit_tag:' + z)[1].split(":")[0],
                'submit_tag_value': pip.split('Submit_tag:' + z)[1].split(z)[0].split(":")[1],
                'Form_id': pip.split('Form_id:' + z)[1].split(z)[0],
                'Form_Type': pip.split('Form_Type:' + z)[1].split(z)[0],
                'database_link': pip.split('database_link:' + z)[1].split(z)[0].replace('\n', ''),
                'Log_test': pip.split('Log_test:' + z)[1].split(z)[0].replace('\n', ''), # or 8080 or whatever
                'Log_out': pip.split('Log_out:' + z)[1].split(z)[0].replace('\n', '') # or 8080 or whatever


            }
            try:
                proxy_info['pre_Link_part'] = pip.split('Link_pre_part:' + z)[1].split(z)[0]
            except:
                proxy_info['pre_Link_part'] = ''

            try:

                proxy_info['submit_tag_name2'] = pip.split('Submit_tag2:' + z)[1].split(":")[0]
                proxy_info['Link_part'] = pip.split('Link_part:' + z)[1].split(z)[0]

                proxy_info['user_tag2'] = pip.split('Form_Tag2:' + z)[1].split(":")[0]
                proxy_info['pass_tag2'] = pip.split('Form_Tag2:' + z)[1].split(z)[0].split(":")[1],
                proxy_info['submit_tag_value2'] = pip.split('Submit_tag2:' + z)[1].split(z)[0].split(":")[1]
                proxy_info['Form_id2'] = pip.split('Form_id2:' + z)[1].split(z)[0]
                proxy_info['Form_Type2'] = pip.split('Form_Type2:' + z)[1].split(z)[0].replace('\n',
                                                                                               '') # or 8080 or whatever
                proxy_info['Log_test2'] = pip.split('Log_test2:' + z)[1].split(z)[0].replace('\n',
                                                                                             '') # or 8080 or whatever
                proxy_info['input_type2'] = pip.split('input_type2:' + z)[1].split(z)[0].replace('\n',
                                                                                                 '') # or 8080 or whatever

            except:
                proxy_info['submit_tag_name2'] = ''

                # proxy_="http://%(user)s:%(pass)s@%(host)s:%(port)s" % proxy_info
                # proxy_handler = urllib2.ProxyHandler({"http" : "http://%(user)s:%(pass)s@%(host)s:%(port)s" % proxy_info})
        except:
            try:
                proxy_info = {
                    'Form_Tag': pip.split('Form_Tag:')[1].replace('\n', '') # or 8080 or whatever
                }
            except:
                proxy_info = {}

        return proxy_info

    def splinter0(self):
        from splinter import Browser

        with Browser('firefox') as browser:
            browser.visit(self.url)
            browser.find_by_name('element_name').click()

    def login_to_site(self, link, form_data, proxy=[], User_Pass=[]):
        self.url = "%(ezproxy_host)s" % form_data
        self.database_link = "%(database_link)s" % form_data
        self.submit_tag_name2 = '%(submit_tag_name2)s' % form_data
        self.log_out = {
            'log_out': "%(Log_out)s" % form_data,
            'METODE': form_data['METODE']}

        username = "%(user)s" % form_data
        password = "%(pass)s" % form_data
        user_tag = "%(user_tag)s" % form_data
        pass_tag = "%(pass_tag)s" % form_data
        Form_id = "%(Form_id)s" % form_data
        Form_id2 = "%(Form_id2)s" % form_data
        log_done = "%(Log_test)s" % form_data
        self.Log_test2 = "%(Log_test2)s" % form_data
        self.Log_test = "%(Log_test)s" % form_data
        site = urlparse2(link).hostname
        br = mechanize.Browser(factory=mechanize.RobustFactory())
        # Browser options
        br.set_handle_robots(False)
        br.set_handle_referer(True)
        br.set_handle_refresh(True)

        br.set_handle_equiv(True)
        br.set_handle_gzip(True)
        br.set_handle_redirect(True)
        policy = mechanize.DefaultCookiePolicy(rfc2965=True)
        cj = mechanize.LWPCookieJar(policy=policy)
        # cj = cookielib.LWPCookieJar()
        # cj.revert(cookie3)
        opener = mechanize.build_opener(mechanize.HTTPCookieProcessor(cj))

        br.set_cookiejar(cj)
        self.cookies_dir = os.getcwd().replace('\\', '/') + '/sites_proxy/' + site + '/cookies'
        if not os.path.isdir(self.cookies_dir):
            os.mkdir(self.cookies_dir)
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        self.cookies = self.cookies_dir + '/' + ''.join([random.choice(chars) for x in range(5)]) + ".txt"

        cj.save(self.cookies)
        # Follows refresh 0 but not hangs on refresh > 0
        br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=1)

        # Want debugging messages?
        # User-Agent (this is cheating, ok?)
        # br.addheaders = [('User-agent',
        #                   'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')]
        # br.addheaders =[('Content-type', 'application/x-www-form-urlencoded'), ('Content-length', '39'), ('Referer', 'http://lib.just.edu.jo/login?url='), ('Host', 'lib.just.edu.jo'), ('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')]

        br.addheaders = [
            ('User-agent',
             'Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:24.0) Gecko/20100101 Firefox/24.0'),
             #'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
            ('Accept',
             'text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5;application/json;text/javascript;*/*'),
            ('Accept-Language', 'en,hu;q=0.8,en-us;q=0.5,hu-hu;q=0.3'),
            ('Accept-Encoding', 'gzip, deflate'),
            ('Accept-Charset', 'ISO-8859-1,utf-8;q=0.7,*;q=0.7'),
            ('Keep-Alive', '300'),
            ('Connection', 'keep-alive'),
            ('Cache-Control', 'max-age=0'),
            ('Referer', self.url),
            ('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8'),
            ('X-Requested-With', 'XMLHttpRequest')
        ]

        cj.add_cookie_header(br)
        #
        # req = urllib2.Request(url, txheaders)
        # req2 = urllib2.urlopen(req)
        # print req2
        if proxy != [] and not (re.findall('None:None', proxy)):
            br.proxies = br.set_proxies({"http": proxy})
            # br.proxies=br.set_proxies( proxy)

        if User_Pass != [] and not (re.findall('None:None', User_Pass)):
            br.add_proxy_password(User_Pass.split(":")[0], User_Pass.split(":")[1])

        try:
            openerdirector = br.open(self.url)
            html = openerdirector.read()
            print html
        except urllib2.HTTPError, e:
            print "Got error code", e.code
            # try:
            #     br.open(self.url)
            # except urllib2.HTTPError, e:
            #     print "Got error code", e.code
        except urllib2.URLError, e:
            return [], self.cookies, [], [], 0, self.log_out
            # print "Got error code", e.code

        # os.environ['http_proxy']=''

        if br.forms():
            print [form for form in br.forms()]
            # br.select_form(name="USER")
            # [f.id for f in br.forms()]
            formcount = done = 0
            for form in br.forms():
                try:
                    form_id = form.attrs['id']
                except:
                    form_id = ''
                if form_id == Form_id:
                    br.form = form
                    done = 1
                if done == 0: formcount = formcount + 1

            formcount = 0
            for frm in br.forms():
                try:
                    form_id = form.attrs['id']
                except:
                    form_id = ''
                if str(form_id) == Form_id2:
                    done = 1
                if done == 0: formcount = formcount + 1

            br.select_form(nr=formcount)
            # br.select_form(nr = 0)
            # self.submit_tag_value2='%(submit_tag_value2)s'%form_data
            # self.Form_id2='%(Form_id2)s'%form_data
            # self.Form_Type2='%(Form_Type2)s'%form_data
            if '%(user_tag)s' % form_data != '':
                br[user_tag] = username
                br[pass_tag] = password
            br.submit()
            # br.form.click("submit")

        html = br.response().get_data()
        print br.response().get_data()
        # print current url
        print "We are now at:", br.geturl()
        # print error
        if br.geturl() == log_done:
            print "Login Failed"
        else:
            print "Successfully logged in"

        if self.submit_tag_name2 != '' and re.findall(self.Log_test2, html):
            if br.forms():
                pass
                for form in br.forms():
                    print form
                # print [form for form in br.forms()]
                # br.select_form(name="USER")
            # [f.id for f in br.forms()]
            formcount = done = 0
            for form in br.forms():
                try:
                    form_id = form.attrs['id']
                except:
                    form_id = ''
                if form_id == Form_id:
                    br.form = form
                    done = 1
                if done == 0: formcount = formcount + 1

            formcount = 0
            for frm in br.forms():
                try:
                    form_id = form.attrs['id']
                except:
                    form_id = ''
                if str(form_id) == Form_id:
                    done = 1
                if done == 0:
                    formcount = formcount + 1

            br.select_form(nr=formcount)
            # br.select_form(nr = 0)
            if '%(user_tag2)s' % form_data != '':
                br[user_tag] = username
                br[pass_tag] = password
            br.submit()

        html = br.response().get_data()
        print br.response().get_data()
        if re.findall(log_done, html):
        # if log_done in br.response().get_data():
            print ("You are logged on to the Public Access to Court Electronic "
                   "Records (PACER) Case Search website as " + username + ". All costs "
                                                                          "will be billed to this account.")
            # print "<li><a>"
            # print (link)
            # print "</a></li>"
            # print "<li><a>"
            # print link.base_url
            # print "</a></li>"
            self.site = urlparse2(link).hostname
            site2 = form_data['database_link']
            self.base_url = 'http://' + self.site + '.' + site2
            ez_link = 'http://' + self.site + '.' + site2 + link.split(self.site)[1]
            cj.save(self.cookies)
            # for link1 in br.links():

            #     # http://www.rfc-editor.org/rfc/rfc2606.txt
            #     if re.findall(self.site, link1.url):
            #         print(link1)
            #         # Link(base_url='http://www.example.com/', url='http://www.rfc-editor.org/rfc/rfc2606.txt', text='RFC 2606', tag='a', attrs=[('href', 'http://www.rfc-editor.org/rfc/rfc2606.txt')])
            #         print(link1.url)
            #         print('match found')
            #         # match found
            #         break
            #
            # br.follow_link(link1)   # link still holds the last value it had in the loop
            # print(br.geturl())
            # req = br.click_link(link1)
            # html = br.open(req).read()
            html2 = br.open(ez_link).read()
            print html2
            br.set_cookiejar(cj)
            cj.save(self.cookies, ignore_discard=True, ignore_expires=True)
            # cj.save(self.cookies, ignore_discard=False, ignore_expires=False)
            # br._ua_handlers['_cookies'].cookiejar.save(self.cookies, ignore_discard=True, ignore_expires=True)
            # br._ua_handlers['_cookies'].cookiejar.save(self.cookies)#, ignore_discard=True, ignore_expires=True)
            # cookiefile=open(self.cookies,'w')
            # cookiestr=''
            # for c in br._ua_handlers['_cookies'].cookiejar:
            #     cookiestr+=c.name+'='+c.value+';'
            # cookiefile.write(cookiestr)
            self.br = br;
            self.cj = cj;
            # time_diff = str(round(time.time() - time0, 2))
            links, title = self.link_tag_find(html2, self.base_url)
            # mechanize._sockettimeout._GLOBAL_DEFAULT_TIMEOUT = 300
            # socket=import_mod(from_module='socket')
            # socket.setdefaulttimeout(300)
            if ( links!=[] ):
               # return html2, self.cookies, links, title, 0, self.log_out
               pass
               try:
                   links11=links
                   br.set_cookiejar(cj)
                   openerdirector = br.open(links)
               except:
                   links11=links[0]
                   br.set_cookiejar(cj)
                   openerdirector = br.open(links[0])
            else:
                 return html, self.cookies, [], [], 0, self.log_out
            try:
                if (openerdirector._headers.dict['content-type']) == 'application/pdf':
                    length = long(openerdirector._headers.dict['content-length'])
                    ok = True
                else:
                    length = 0
            except:
                length = 0

            for link1 in br.links(url_regex=".pdf"):


                # http://www.rfc-editor.org/rfc/rfc2606.txt
                # if re.findall(links11, link1.url):
                    print(link1)
                    # Link(base_url='http://www.example.com/', url='http://www.rfc-editor.org/rfc/rfc2606.txt', text='RFC 2606', tag='a', attrs=[('href', 'http://www.rfc-editor.org/rfc/rfc2606.txt')])
                    print(link1.url)
                    print('match found')
                    # match found
                    break
            time.sleep(2)
            br.follow_link(link1)   # link still holds the last value it had in the loop
            # print(br.geturl())
            pdf_link=br.geturl()
            if pdf_link:
                br.set_cookiejar(cj)
                cj.save(self.cookies, ignore_discard=True, ignore_expires=True)
                # return html2, self.cookies, pdf_link, title, 0, self.log_out

            localName = LINK(PDF_Dir=PDF_Dir, Watermarked_PDF_Files_Dir=Watermarked_PDF_Files_Dir).filename2(
                pdf_link)
            f1 = self.br.retrieve(pdf_link, localName.pdf_Folder_filename)
            if f1:
                cj.save(self.cookies, ignore_discard=True, ignore_expires=True)
                # return f1[0], self.cookie3
                return f1[0], self.cookies, pdf_link, title, 0, self.log_out
            # f1 = br.retrieve(pdf_link)
            # if length==0:
            #     return html2, self.cookies, [], [], 0, self.log_out
            # dlength = 0
            piece_size = 4096 # 4 KiB
            # piece_size =1024*1024 # 1MB
            data = ''

            newdata = openerdirector.read(piece_size)
            print newdata

            f1 = br.retrieve(link1)
            if f1:
                self.cj.save(self.cookie3)
                return f1[0], self.cookie3 #,pdf_path
            import pickle
            # with open(self.cookies, 'wb') as f:
            #     pickle.dump(cj, f)
            # html,pr,upss,cookies=web().download_mechanism_link(links,'None:None',cookies=self.cookies);mech=1
            # print html
            # html, cookies2 = MECAHNIZM('None:None', '', cookies=self.cookies, url=links11).download_pdf_br(links11)
            print html

            # if link != []:
            #     return html2, self.cookies, links, title, 0, self.log_out
            # return html2, self.cookies, [], [], 0, self.log_out

            # frontpage,cookies = MECAHNIZM([],[],cookies=self.cookies,url=ez_link).speed_download(ez_link)

            request = br.request
            header = request.header_items()
            # header=request.get_header()

            # Browser options
            br.set_handle_robots(False)
            # br.set_handle_referer(True)
            # br.set_handle_refresh(True)
            #
            br.set_handle_equiv(True)
            br.set_handle_gzip(True)
            # br.set_handle_redirect(True)
            cj = cookielib.LWPCookieJar()
            # cj.revert(cookie3)
            opener = mechanize.build_opener(mechanize.HTTPCookieProcessor(cj))

            br.set_cookiejar(cj)

            cj.save(self.cookies)
            # Follows refresh 0 but not hangs on refresh > 0
            br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=1)

            time0 = time.time()

            # request = urllib2.Request(ez_link, None, header)
            # openerdirector = br.open(request)
            # br.addheaders(header)
            openerdirector = br.open(links11)
            try:
                if (openerdirector._headers.dict['content-type']) == 'application/pdf':
                    length = long(openerdirector._headers.dict['content-length'])
                    ok = True
                else:
                    length = 0
            except:
                length = 0
            dlength = 0
            # piece_size = 4096 # 4 KiB
            piece_size = 1024 * 1024 # 1MB
            data = ''
            while True:
                newdata = openerdirector.read(piece_size)
                dlength += len(newdata)
                data += newdata
                if length != 0:
                    status = r"%10d [%3.2f%%]" % (dlength, dlength * 100. / length)
                    status = status + chr(8) * (len(status) + 1)
                    print status
                    # pdf_path=PDF_File().file_save(data, "PDF_Files\\", localName.filename)
                    # if onprogress:
                    #     onprogress(length,dlength)
                if not newdata:
                    cj.save(self.cookies)
                    break

            self.br = br;
            self.cj = cj;
            time_diff = str(round(time.time() - time0, 2))
            links, title = self.link_tag_find(data, self.base_url)
            if links != []:
                return data, self.cookies, links, title, time_diff
            return data, self.cookies #,pdf_path


        else:
        # raise ValueError("Could not login to PACER Case Search. Check your "
        #              "username and password")
            return html, self.cookies, [], [], 0, self.log_out
        return html, self.cookies, [], [], 0, self.log_out

    def link_tag_find(self, html, base_url):
        # try:
        #     # title=LINK().find_my_tilte(data=html,start_dash='<h1 class="article-title"',end_dash='1>',make_url=False)
        #     # title = LINK().find_my_tilte(data=html, start_dash='type="image/x-icon"><title>', end_dash='</title>',make_url=False)
        #     title=LINK().find_my_tilte(data=html,start_dash='<title>',end_dash='</title>',make_url=False)
        # except:
        #     title = ''
        #
        # links = LINK().find_my_tilte(data=html, start_dash='<a id="pdfLink" href="', end_dash='"', make_url=True)
        #
        # if links == [] or links == '':
        #     links = LINK().soap_my(data=html, tag='pdfLink', attr='a', href='href', url=base_url)
        # if links == '' or links == []:
        #     links = LINK().soap_my(data=html, tag='title="Download PDF" ', attr='a', href='href', url=base_url)
        # if title == '' or title == []:
        #     title = LINK().soap_my(data=html, tag='class="article-title"', attr='h1', href='', url=base_url)
        # if title == '' or title == []:
        #     title = LINK().soap_my(data=html, tag='<title>', attr='', href='', url=base_url)
        # if links != []:
        #     pass
        [links, title] = link_tag_find(html, base_url)
        return links, title

    def twill_download(self, url, cookies):
        # self.url="%(ezproxy_host)s"%form_data
        # self.database_link="%(database_link)s"%form_data
        # self.username="%(user)s"%form_data
        # self.password="%(pass)s"%form_data
        # self.user_tag="%(user_tag)s"%form_data
        # self.pass_tag="%(pass_tag)s"%form_data
        # self.Form_id="%(Form_id)s"%form_data
        # self.submit_tag_name="%(submit_tag_name)s"%form_data
        # self.submit_tag_value="%(submit_tag_value)s"%form_data
        # self.Form_Type="%(Form_Type)s"%form_data
        # self.log_done="%(Log_test)s"%form_data
        link = url['link'];
        lg = url['log_out'];
        url_logout = lg['log_out'];
        ez_link = lg['ez_link']
        twil__headers = lg['headers']
        try:
            link = lg['pdf_link']
            # site = urlparse2(link.absolute_url).hostname
        except:
            pass
            # site = urlparse2(link).hostname





        # self.a.config("readonly_controls_writeable", 1)
        # self.b = self.a.get_browser()
        # self.b.set_agent_string("Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.14) Gecko/20080404 Firefox/2.0.0.14")
        # self.b.clear_cookies()
        twill = import_mod(from_module='twill')

        # t_com = twill.commands
        # t_com.reset_browser
        # t_com.reset_output
        t_com = twill.commands

        ## get the default browser
        t_brw = t_com.get_browser()
        # try:
        #     t_brw.set_agent_string(
        #         "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.14) Gecko/20080404 Firefox/2.0.0.14")
        #
        #     t_com.add_extra_header('User-agent',
        #                            'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')
        #     t_com.add_extra_header('Accept',
        #                            'text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5;application/json;text/javascript;*/*')
        #     t_com.add_extra_header('Accept-Language', 'en,hu;q=0.8,en-us;q=0.5,hu-hu;q=0.3')
        #     t_com.add_extra_header('Accept-Encoding', 'gzip, deflate')
        #     t_com.add_extra_header('Accept-Charset', 'ISO-8859-1,utf-8;q=0.7,*;q=0.7')
        #     t_com.add_extra_header('Keep-Alive', '300')
        #     t_com.add_extra_header('Connection', 'keep-alive')
        #     t_com.add_extra_header('Cache-Control', 'max-age=0')
        #     t_com.add_extra_header('Referer', ez_link)
        #     t_com.add_extra_header('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8')
        #     t_com.add_extra_header('X-Requested-With', 'XMLHttpRequest')
        #
        #     t_com.add_extra_header('User-agent',
        #                            'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')
        #     t_com.add_extra_header('Accept',
        #                            "text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5;application/json;text/javascript;*/*")
        #     t_com.add_extra_header('Accept-Language', 'en,hu;q=0.8,en-us;q=0.5,hu-hu;q=0.3')
        #     t_com.add_extra_header('Accept-Encoding', 'gzip, deflate')
        #     t_com.add_extra_header('Accept-Charset', 'ISO-8859-1,utf-8;q=0.7,*;q=0.7')
        #     t_com.add_extra_header('Keep-Alive', '300')
        #     t_com.add_extra_header('Connection', 'keep-alive')
        #     t_com.add_extra_header('Cache-Control', 'max-age=0')
        #     t_com.add_extra_header('Referer', ez_link)
        #     t_com.add_extra_header('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8')
        #     t_com.add_extra_header('X-Requested-With', 'XMLHttpRequest')
        # except:
        #     pass
        t_brw.set_agent_string(twil__headers)
        # t_brw._browser.addheaders = []
        # del twil__headers[-1]
        # twil__headers += [('Referer', ez_link)]
        # t_brw._browser.addheaderst=twil__headers
        # t_com.add_extra_header('Referer', ez_link) #used foe some exproxies
        # cookies=cookies.replace('/','\\')
        t_brw.load_cookies(cookies)
        # socket=import_mod(from_module='socket')
        # socket.setdefaulttimeout(300)
        ## open the url
        # url = 'http://google.com'
        # t_brw.find_link(link)
        # t_brw.go(link)
        print '@@@@@@@@@@@@@ link download by twill is @@@@@@@@@@@@'
        print link
        print '@@@@@@@@@@@@@ link download by twill is @@@@@@@@@@@@'
        # import sys
        # sys.exit(1)
        # t2=t_brw.find_link('Download PDF')
        # t_brw.follow_link(t2)

        try:
            try:
                t2=t_brw.find_link('Download PDF')
                t_brw.follow_link(t2)
            except:
              t_brw = t_com.get_browser()
              t_brw.set_agent_string(twil__headers)
              t_brw.load_cookies(cookies)

              if len(link.absolute_url[0])!=1:
                s = link.absolute_url[0]
                s2 = type('test', (object,), {})()
                s2.absolute_url=link.absolute_url[0]
                s2.base_url=link.base_url
                print s2.absolute_url
                t_brw.follow_link(s2)
              else:
                t_brw.follow_link(link)
        except:
            # t_brw.set_agent_string(twil__headers)
            # t_com.add_extra_header('Referer', ez_link)
            try:
               if len(link.absolute_url[0])!=1:
                s = link.absolute_url[0]
                s2 = type('test', (object,), {})()
                s2.absolute_url=link.absolute_url[0]
                s2.base_url=link.base_url
                print s2.absolute_url
                t_brw.go(s2.absolute_url)
               else:
                   t_brw.go(link.absolute_url)

            except:
                t_brw.set_agent_string(twil__headers)
                t_com.add_extra_header('Referer', ez_link)
                t_brw.go(link)
            # class link_n(object):
            #     def __init__(self):
            #         self.absolute_url = link
            #         self.base_url = ez_link
            #         self.url=ez_link
            #     def url(self):
            #         return self
            # link=link_n.url
        # t_brw.follow_link(link)
        html0 = t_brw.result.page

        print '@@@@@@@@@@@@@ html0 download by twill is @@@@@@@@@@@@'
        print html0[:20]
        print '@@@@@@@@@@@@@ html0 download by twill is @@@@@@@@@@@@'
        # time.sleep(10)




        link2 = t_brw.result.url
        link2 = link.absolute_url
        if not (html0[:4] == '%PDF') or html0 == []:
            t_brw.set_agent_string(twil__headers)
            t_com.add_extra_header('Referer', ez_link)
            t_brw.go(link2)
            html2 = t_brw.result.page
            html, cookies = MECAHNIZM('', '', cookies=cookies, url=link2).speed_download(link2)
            # html3,pr,upss,cookies=web().download_mechanism_link(link,'',cookies=cookies)
            if not (html[:4] == '%PDF') or html == []:
                t_brw.save_cookies(cookies)
                t_brw = t_com.get_browser()
                t_brw.set_agent_string(
                    "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.14) Gecko/20080404 Firefox/2.0.0.14")
                t_brw.load_cookies(cookies)
                # socket=import_mod(from_module='socket')
                # socket.setdefaulttimeout(300)
                html3, pr, upss, cookies = web().download_mechanism_link(link, '', cookies=cookies)
                t_brw.go(link2)
                html = t_brw.result.page

                print '@@@@@@@@@@@@@ html download by twill is @@@@@@@@@@@@'
                print html
                print '@@@@@@@@@@@@@ html download by twill is @@@@@@@@@@@@'
                # time.sleep(10)
        else:
            html = html0
        t_brw.go(url_logout)
        os.remove(cookies)
        return html


    def twill_find_link(self, link, form_data):
        # from goto import goto, label
        self.url = "%(ezproxy_host)s" % form_data
        self.database_link = "%(database_link)s" % form_data
        self.Link_part = "%(Link_part)s" % form_data
        self.pre_Link_part = "%(pre_Link_part)s" % form_data
        self.username = "%(user)s" % form_data
        self.password = "%(pass)s" % form_data
        self.user_tag = "%(user_tag)s" % form_data
        self.pass_tag = "%(pass_tag)s" % form_data
        self.Form_id = "%(Form_id)s" % form_data
        self.submit_tag_name = "%(submit_tag_name)s" % form_data
        self.submit_tag_value = "%(submit_tag_value)s" % form_data
        self.Form_Type = "%(Form_Type)s" % form_data
        self.Log_test2 = "%(Log_test2)s" % form_data
        self.input_type2 = form_data['input_type2']
        self.log_done = "%(Log_test)s" % form_data
        self.log_out = {
            'log_out': "%(Log_out)s" % form_data,
            'METODE': form_data['METODE']}

        self.submit_tag_name2 = '%(submit_tag_name2)s' % form_data

        site = urlparse2(link).hostname

        self.cookies_dir = os.getcwd().replace('\\', '/') + '/sites_proxy/' + site + '/cookies'
        if not os.path.isdir(self.cookies_dir):
            os.mkdir(self.cookies_dir)
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        self.cookies = self.cookies_dir + '/' + ''.join([random.choice(chars) for x in range(5)]) + ".txt"
        # self.a.config("readonly_controls_writeable", 1)
        # self.b = self.a.get_browser()
        # self.b.set_agent_string("Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.14) Gecko/20080404 Firefox/2.0.0.14")
        # self.b.clear_cookies()
        twill = import_mod(from_module='twill')
        import twill
        t_com = twill.commands
        t_com.reset_browser
        t_com.reset_output
        t_com = twill.commands
        ## get the default browser
        t_brw = t_com.get_browser()
        # t_brw.set_agent_string("Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.14) Gecko/20080404 Firefox/2.0.0.14")
        # t_com.add_extra_header('User-agent',
        #                        'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')
        t_com.add_extra_header('User-agent',
                               'Mozilla/5.0 (Windows NT 6.1; rv:18.0) Gecko/20100101 Firefox/18.0')

        t_com.add_extra_header('Accept',
                               'text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5;application/json;application/atom+xml;text/javascript;*/*')
        t_com.add_extra_header('Accept-Language', 'en,hu;q=0.8,en-us;q=0.5,hu-hu;q=0.3')
        t_com.add_extra_header('Accept-Encoding', 'gzip, deflate')
        t_com.add_extra_header('Accept-Charset', 'ISO-8859-1,utf-8;q=0.7,*;q=0.7')
        t_com.add_extra_header('Keep-Alive', '3000')
        t_com.add_extra_header('Connection', 'keep-alive')
        t_com.add_extra_header('Cache-Control', 'max-age=0, no-cache, no-store')

        t_com.add_extra_header('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8')
        # t_com.add_extra_header('Content-Type', 'application/x-www-form-urlencoded; charset=latin-1')
        t_com.add_extra_header('X-Requested-With', 'XMLHttpRequest')

        t_com.add_extra_header('X-ELS-ResourceVersion', 'XOCS')
        t_com.add_extra_header('Referer', self.url)

        ## open the url
        # url = 'http://google.com'

        t_com.save_cookies(self.cookies)
        t_brw.load_cookies(self.cookies)
        # print t_com.show_extra_headers()
        # print t_com.show_cookies()
        # try:t_brw.go(self.log_out['log_out'])
        # except:pass
        try:
            t_brw.go(self.url)
        except:
            html=[];links=[];title=[];time_diff='0'
            return html, self.cookies, links, title, time_diff, self.log_out
        # t_brw.reload
        html = t_brw.result.page
        # print t_com.show_extra_headers()
        # print t_com.show_cookies()
        print html
        # print fill_login_form(url, html, "john", "secret")
        if re.findall(self.log_done, html):
            # goto .find
            print ("You are logged on to the Public Access to Court Electronic "
                   "Records (PACER) Case Search website as " + self.url + ". All costs "
                                                                          "will be billed to this account.")

            # t_brw.go(self.database_link)
            # site = urlparse2(link).hostname
            # site2 = urlparse2(self.url).hostname
            link2 = t_brw.result.url
            site2 = self.Link_part
            if self.pre_Link_part != '':
                base_url = 'http://' + site + '.' + site2
                ez_link = 'http://' + site + '.' + site2 + link.split(site)[1]
            else:
                base_url = 'http://' + site2
                ez_link = 'http://' + site2 + link.split(site)[1]

            time0 = time.time()
            t_brw.go(ez_link)
            time_diff = str(round(time.time() - time0, 2))
            html = t_brw.result.page

            # f=1
            # links=LINK().find_my_tilte(data=html,start_dash='<a id="pdfLink" href="',end_dash='"',make_url=True)
            #
            # if links==''or links==[]:
            #     links =LINK().soap_my(data=html, tag='title="Download PDF" ', attr='a', href='href',url=base_url)
            #
            # if links==[] or links=='':
            #     links =LINK().soap_my(data=html, tag="Download PDF", attr='a', href='href',url=base_url)
            # if links==[] or links=='':
            #     links=LINK().soap_my(data=html,tag='pdfLink',attr='a',href='href',url=base_url)
            # re.findall('if(SDM.pageType'.html)
            # if self.submit_tag_name2!='' and not re.findall ( "SDM.pageType",html ):
            # if self.submit_tag_name2!='' and  re.findall ( self.log_done2,html ):
            if self.submit_tag_name2 != '' and re.findall(self.Log_test2, html): #"Choose Organization",html ):
                self.submit_tag_value2 = '%(submit_tag_value2)s' % form_data
                self.Form_id2 = '%(Form_id2)s' % form_data
                self.Form_Type2 = '%(Form_Type2)s' % form_data
                all_forms = t_brw.get_all_forms()         ## this returns list of form objects
                print "Forms:"
                t_brw.showforms()

                ## now, you have to choose only that form, which is having POST method

                self.formnumber = 0
                formnumber = 1
                for each_frm in all_forms:
                    self.formnumber = 1 + self.formnumber
                    attr = each_frm.attrs             ## all attributes of form
                    try:
                        form_id = each_frm.attrs['id']
                    except:
                        form_id = ''

                    if each_frm.method == 'POST' and (form_id == self.Form_id2 ):
                        ctrl = each_frm.controls
                        for ct in ctrl:
                            if ct.type == self.input_type2:     ## i did it as per my use, you can put your condition here
                                # ct._value = "twill"

                                # t_com.clicked(each_frm,'%(user_tag2)s'%form_data)            ## clicked takes two parameter, form object and button name to be clicked.

                                t_com.showforms()
                                t_com.fv(self.formnumber, '%(user_tag2)s' % form_data, each_frm.controls[3]._value)
                                t_com.showforms()
                                t_com.submit()
                                content = t_com.show()
                                break
                                # print 'debug twill post content:', content


                        # t_com.formclear(formnumber)
                        # va=each_frm.controls[3]._value
                        # t_com.fv(self.formnumber, '%(user_tag2)s'%form_data, each_frm.controls[3]._value)
                        # # t_com.fv(self.formnumber, self.pass_tag, self.password)
                        # print "Forms:"
                        # t_brw.showforms()
                        # # t_com.submit(self.formnumber)
                        # # t_brw.submit(self.submit_tag_name)
                        # t_com.submit(self.submit_tag_name2)
                        # #
                        # content = t_com.show()
                        # print 'debug twill post content:', content
                        # t_com.save_cookies(self.cookies)
                        t_brw.save_cookies(self.cookies)
                        t_brw.load_cookies(self.cookies)




            # print t_brw.find_link('http://64.62.211.131:2082/frontend/x3/mail/fwds.html')
            t_brw.save_cookies(self.cookies)
            # print t_com.show_extra_headers()
            # print t_com.show_cookies()
            print t_com.showlinks()
            links2 = t_com.showlinks()
            # print t_brw.result.page
            html = t_brw.result.page
            # print t_com.show_extra_headers()
            headers = t_com.show_extra_headers()

            [links_0, title] = link_tag_find(html, base_url)

            # time0 = time.time()
            # t_brw.load_cookies(self.cookies)
            # t_brw.go(links_0[0])
            # time_diff = str(round(time.time() - time0, 2))
            # html = t_brw.result.page
            # if (not (html.endswith('.pdf'))) and html[:4]!='%PDF' :
            #     return html, self.cookies, [], [], 0, self.log_out
            if len(links_0)>1:
                base_url_list=[];links_list=[]
                for links in links_0:
                    if not (links == '' or links == []):
                        if self.pre_Link_part != '':
                            base_url = 'http://' + site + '.' + site2
                            links = 'http://' + site + '.' + site2 + links.split(site)[1]
                            if site2 == '':
                                base_url = 'http://' + self.pre_Link_part
                                links = 'http://' + self.pre_Link_part + links.split(site)[1]
                        else:
                            if site2 == '':
                                base_url = 'http://'
                                links = 'http://' + links.split(site)[1]
                            else:
                                base_url = 'http://' + site2
                                try:
                                    links = 'http://' + site2 + links.split(site)[1]
                                except:
                                    links=links_0[0]
                    base_url_list.append(base_url);links_list.append(links)
            elif len(links_0)==1:
                links =links_0
                if not (links == '' or links == []):
                    if self.pre_Link_part != '':
                        base_url = 'http://' + site + '.' + site2
                        links = 'http://' + site + '.' + site2 + links.split(site)[1]
                        if site2 == '':
                            base_url = 'http://' + self.pre_Link_part
                            links = 'http://' + self.pre_Link_part + links.split(site)[1]
                    else:
                        if site2 == '':
                            base_url = 'http://'
                            links = 'http://' + links.split(site)[1]
                        else:
                            base_url = 'http://' + site2
                            links = 'http://' + site2 + links.split(site)[1]
            try:
                links=links_list
                base_url=base_url_list
            except:pass
            try:
                # title=LINK().find_my_tilte(data=html,start_dash='<h1 class="article-title"',end_dash='1>',make_url=False)
                if title=='' or title==[]:
                    title = LINK().find_my_tilte(data=html, start_dash='type="image/x-icon"><title>', end_dash='</title>',
                                                 make_url=False)
            except:
                title = ''

            links1 = t_brw.find_link('Download PDF')

            if links1 == '' or links1 == [] or links1 == 'None' or links1 == None:
                links = LINK().find_my_tilte(data=html, start_dash='<a id="pdfLink" href="', end_dash='"',
                                             make_url=True)
                if links == '' or links == []:
                    links = LINK().soap_my(data=html, tag='title="Download PDF" ', attr='a', href='href', url=base_url)

                if links == [] or links == '':
                    links = LINK().soap_my(data=html, tag="Download PDF", attr='a', href='href', url=base_url)
                if links == [] or links == '':
                    links = LINK().soap_my(data=html, tag='pdfLink', attr='a', href='href', url=base_url)

            else:
                links = links1.absolute_url
                self.log_out = {
                    'log_out': "%(Log_out)s" % form_data,
                    'METODE': form_data['METODE'],
                    'ez_link': ez_link,
                    'headers': t_brw._browser.addheaders,
                    'pdf_link': links1}

            if title == '' or title == []:
                title = LINK().soap_my(data=html, tag='class="article-title"', attr='h1', href='', url=base_url)
            if title == '' or title == []:
                title = LINK().soap_my(data=html, tag='<title>', attr='', href='', url=base_url)
            if links != []:
            # t_brw.go(links)
            # html0=t_brw.result.page
            # print '@@@@@@@@@@@@@ html0 download by twill is @@@@@@@@@@@@'
            # print html0
            # print '@@@@@@@@@@@@@ html0 download by twill is @@@@@@@@@@@@'
            # time.sleep(10)
            # link2=t_brw.result.url
            # print '@@@@@@@@@@@@@ time.sleep(10) download by twill is @@@@@@@@@@@@'
            # print link2
            # print '@@@@@@@@@@@@@ time.sleep(10) download by twill is @@@@@@@@@@@@'
            # time.sleep(10)
            # if  not (html0[:4]=='%PDF') or html0==[] :
            #     html2,cookies = MECAHNIZM('','',cookies=self.cookies,url=link2).speed_download(link2)
            #     print '@@@@@@@@@@@@@ MECAHNIZM download by twill is @@@@@@@@@@@@'
            #     print html2
            #     print '@@@@@@@@@@@@@ MECAHNIZM download by twill is @@@@@@@@@@@@'
            #     time.sleep(10)
                return html, self.cookies, links, title, time_diff, self.log_out
            else:
                return html, self.cookies, links, title, time_diff, self.log_out
            ## get all forms from that URL
        all_forms = t_brw.get_all_forms()         ## this returns list of form objects
        print "Forms:"
        t_brw.showforms()

        ## now, you have to choose only that form, which is having POST method

        self.formnumber = 0
        formnumber = 1
        for each_frm in all_forms:
            self.formnumber = 1 + self.formnumber
            attr = each_frm.attrs             ## all attributes of form
            try:
                form_id = each_frm.attrs['id']
            except:
                form_id = ''

            if each_frm.method == 'POST' and ((form_id == self.Form_id ) or ( str(self.formnumber )== self.Form_id )):


                t_com.formclear(formnumber)
                t_com.fv(self.formnumber, self.user_tag, self.username)
                t_com.fv(self.formnumber, self.pass_tag, self.password)
                all_forms = t_brw.get_all_forms()         ## this returns list of form objects
                print "Forms:"
                t_brw.showforms()
                # t_com.submit(self.formnumber)
                # t_brw.submit(self.submit_tag_name)
                t_com.submit(self.submit_tag_name)
                #
                # html=t_brw.result.page
                # print html
                # content = t_com.show()
                content = t_brw.result.page
                # print 'debug twill post content:', content
                t_com.save_cookies(self.cookies)
                # t_brw.load_cookies(self.cookies)
                if re.findall(self.log_done, content):
                    # label .find
                    print ("You are logged on to the Public Access to Court Electronic "
                           "Records (PACER) Case Search website as " + self.url + ". All costs "
                                                                                  "will be billed to this account.")

                    # t_brw.go(self.database_link)
                    # site = urlparse2(link).hostname
                    # site2 = self.database_link
                    site2 = self.Link_part
                    if self.pre_Link_part != '':
                        base_url = 'http://' + site + '.' + site2
                        ez_link = 'http://' + site + '.' + site2 + link.split(site)[1]
                        if site2 == '':
                            base_url = 'http://' + self.pre_Link_part
                            ez_link = 'http://' + self.pre_Link_part + link.split(site)[1]
                    else:
                        if site2 == '':
                            base_url = 'http://'
                            ez_link = 'http://' + link.split(site)[1]
                        else:
                            base_url = 'http://' + site2
                            ez_link = 'http://' + site2 + link.split(site)[1]

                    time0 = time.time()
                    t_brw.go(ez_link)
                    time_diff = str(round(time.time() - time0, 2))
                    html = t_brw.result.page
                    t_com.save_cookies(self.cookies)
                    # t_brw.load_cookies(self.cookies)
                    # if self.submit_tag_name2!=''and not re.findall ( "SDM.pageType",html ):
                    if self.submit_tag_name2 != '' and re.findall(self.Log_test2, html): #"Choose Organization",html ):
                        self.submit_tag_value2 = '%(submit_tag_value2)s' % form_data
                        self.Form_id2 = '%(Form_id2)s' % form_data
                        self.Form_Type2 = '%(Form_Type2)s' % form_data
                        all_forms = t_brw.get_all_forms()         ## this returns list of form objects
                        print "Forms:"
                        t_brw.showforms()

                        ## now, you have to choose only that form, which is having POST method

                        self.formnumber = 0
                        formnumber = 1
                        for each_frm in all_forms:
                            self.formnumber = 1 + self.formnumber
                            attr = each_frm.attrs             ## all attributes of form
                            try:
                                form_id = each_frm.attrs['id']
                            except:
                                form_id = ''

                            if each_frm.method == 'POST' and (form_id == self.Form_id2 ):
                                ctrl = each_frm.controls
                                for ct in ctrl:
                                    if ct.type == self.input_type2:     ## i did it as per my use, you can put your condition here
                                        # ct._value = "twill"

                                        # t_com.clicked(each_frm,'%(user_tag2)s'%form_data)            ## clicked takes two parameter, form object and button name to be clicked.

                                        t_com.showforms()
                                        # t_com.fv(self.formnumber, form_data['user_tag2'], each_frm.controls[3]._value)
                                        t_com.fv(self.formnumber, form_data['user_tag2'], ct._value)
                                        t_com.showforms()
                                        t_com.submit()
                                        content = t_com.show()
                                        break
                                        # print 'debug twill post content:', content


                                # t_com.formclear(formnumber)
                                # va=each_frm.controls[3]._value
                                # t_com.fv(self.formnumber, '%(user_tag2)s'%form_data, each_frm.controls[3]._value)
                                # # t_com.fv(self.formnumber, self.pass_tag, self.password)
                                # print "Forms:"
                                # t_brw.showforms()
                                # # t_com.submit(self.formnumber)
                                # # t_brw.submit(self.submit_tag_name)
                                # t_com.submit(self.submit_tag_name2)
                                # #
                                # content = t_com.show()
                                # print 'debug twill post content:', content
                                # t_com.save_cookies(self.cookies)
                                t_brw.save_cookies(self.cookies)
                                # cj.save(self.cookies, ignore_discard=True, ignore_expires=True)
                                # t_brw.load_cookies(self.cookies)
                                html = t_brw.result.page[:14100]
                    else:
                        pass
                        # html=html;

                    # print t_brw.find_link('http://64.62.211.131:2082/frontend/x3/mail/fwds.html')

                    # print t_brw._browser.addheaders
                    # print t_com.show_cookies()
                    # print t_com.showlinks()
                    # # print t_brw.result.page
                    # import twill
                    # t_com = twill.commands
                    # ## get the default browser
                    # t_brw = t_com.get_browser()

                    # html=t_brw.result.page[:14100]
                    t_com.save_cookies(self.cookies)


                    # t2=t_brw.find_link('Download PDF')
                    # t_brw.follow_link(t2)
                    if self.log_out['METODE'] == '1+d':
                            try:
                                socket=import_mod(from_module='socket')
                                socket.setdefaulttimeout(3000)
                                # twil__headers=t_brw._browser.addheaders
                                # t_brw.set_agent_string(twil__headers)
                                t_brw.load_cookies(self.cookies)
                                t2=t_brw.find_link('Download PDF')
                                t_brw.follow_link(t2)
                                time_diff = str(round(time.time() - time0, 2))
                                html0=t_brw.result.page
                            except:
                                try:
                                    twil__headers=t_brw._browser.addheaders
                                    t_brw.set_agent_string(twil__headers)
                                    t_brw.load_cookies(self.cookies)
                                    t_brw.follow_link(links1)
                                    if len(links[0])!=1:pass
                                    else:t_brw.follow_link(links1)
                                    html0 = t_brw.result.page
                                    if len(links[0])!=1:t_brw.go(links[0])
                                    else:t_brw.go(links)
                                    time_diff = str(round(time.time() - time0, 2))
                                    html0 = t_brw.result.page
                                except:
                                    print 'error in downloading MEHOD=1+d';html0=''

                    else:
                        html0=''
                    # t_brw.load_cookies(self.cookies)
                    print '@@@@@@@@@@@@@ html0 download by twill is @@@@@@@@@@@@\n'+html0
                    [links, title] = link_tag_find(html, base_url)
                    if len(links[0])!=1:links3=[];links3=links[0];links=[];links.append(links3)

                    # if not (links == '' or links == []):
                    #     if self.pre_Link_part != '':
                    #         base_url = 'http://' + site + '.' + site2
                    #         links = 'http://' + site + '.' + site2 + links.split(site)[1]
                    #         if site2 == '':
                    #             base_url = 'http://' + self.pre_Link_part
                    #             links = 'http://' + self.pre_Link_part + links.split(site)[1]
                    #     else:
                    #         if site2 == '':
                    #             base_url = 'http://'
                    #             links = 'http://' + links.split(site)[1]
                    #         else:
                    #             base_url = 'http://' + site2
                    #             links = 'http://' + site2 + links.split(site)[1]

                    if title == '' or title == []:
                        try:
                            # title=LINK().find_my_tilte(data=html,start_dash='<h1 class="article-title"',end_dash='1>',make_url=False)
                            # title=LINK().find_my_tilte(data=html,start_dash='type="image/x-icon"><title>',end_dash='</title>',make_url=False)
                            title = LINK().find_my_tilte(data=html, start_dash='<title>', end_dash='</title>',
                                                         make_url=False)
                        except:
                            title = ''
                    if links == '' or links == []:
                        links1 = t_brw.find_link('Download PDF')
                    else:
                        try:
                            links1 = t_brw.find_link('Download PDF')
                            links1.absolute_url = links
                        except:links1=[]

                    if links1 == '' or links1 == [] or links1 == None:
                        links = LINK().find_my_tilte(data=html, start_dash='<a id="pdfLink" href="', end_dash='"',
                                                     make_url=True)
                        if links == '' or links == []:
                            [links, title] = link_tag_find(html, base_url)
                            # links =LINK().soap_my(data=html, tag='title="Download PDF" ', attr='a', href='href',url=base_url)

                        if links == [] or links == '': pass
                        # links =LINK().soap_my(data=html, tag="Download PDF", attr='a', href='href',url=base_url)
                        # if links==[] or links=='':
                        #     links=LINK().soap_my(data=html,tag='pdfLink',attr='a',href='href',url=base_url)
                        if self.log_out['METODE'] == '1+d' and  (html0[:4]!='%PDF' or html0[-7:]!='%%EOF' ) :
                            try:
                                t_brw.load_cookies(self.cookies)
                                t_brw.go(links)
                                time_diff = str(round(time.time() - time0, 2))
                                html = t_brw.result.page
                            except:
                                print "error in METOD 1+d"
                                html=[]
                    else:
                        try:
                            links = links1.absolute_url
                        except:
                            links = links1
                        if self.log_out['METODE'] == '1+d'  and  (html0[:4]!='%PDF' or len ( re.findall('%%EOF', html ))==0 ):
                            try:
                                socket=import_mod(from_module='socket')
                                t2=t_brw.find_link('Download PDF')
                                t_brw.follow_link(t2)
                                time_diff = str(round(time.time() - time0, 2))
                                html=t_brw.result.page
                            except:
                                try:
                                    twil__headers=t_brw._browser.addheaders
                                    t_brw.set_agent_string(twil__headers)
                                    t_brw.load_cookies(self.cookies)
                                    t_brw.follow_link(links1)
                                    if len(links[0])!=1:pass
                                    else:t_brw.follow_link(links1)
                                    html0 = t_brw.result.page
                                    if len(links[0])!=1:t_brw.go(links[0])
                                    else:t_brw.go(links)
                                    time_diff = str(round(time.time() - time0, 2))
                                    html = t_brw.result.page
                                except:
                                    print 'error in downloading'
                                    return [], self.cookies, [], [], 0, self.log_out



                        twil__headers=t_brw._browser.addheaders
                        del twil__headers[-1]
                        twil__headers += [('Referer', ez_link)]
                        self.log_out = {
                            'log_out': "%(Log_out)s" % form_data,
                            'METODE': form_data['METODE'],
                            'ez_link': ez_link,
                            # 'headers': t_brw._browser.addheaders,
                            'headers': twil__headers,
                            'pdf_link': links1}


                    if title == '' or title == []:
                        title = LINK().soap_my(data=html, tag='class="article-title"', attr='h1', href='', url=base_url)
                    if title == '' or title == []:
                        title = LINK().soap_my(data=html, tag='<title>', attr='', href='', url=base_url)
                    if    (html0[:4]=='%PDF' or len ( re.findall('%%EOF', html ))!=0):html=html0

                    if links != [] and self.log_out['METODE'] == '1+d+d' and  (html0[:4]!='%PDF' or html0[-7:]!='%%EOF' ):


                        socket=import_mod(from_module='socket')
                        # socket.setdefaulttimeout(3000)
                        t_brw.load_cookies(self.cookies)
                        # if len(links1.absolute_url[0])!=1:
                        #     s = links1.absolute_url[0]
                        #     s2 = type('test', (object,), {})()
                        #     s2.absolute_url=links1.absolute_url[0]
                        #     s2.base_url=links1.base_url
                        #     print s2.absolute_url
                        #     t_brw.follow_link(s2)
                        #     t_brw.go(s2.absolute_url)
                        # t_brw.go(links)
                        # content = t_com.show()
                        headers = t_com.show_extra_headers()
                        twil__headers=t_brw._browser.addheaders
                        # t_brw.set_agent_string(twil__headers)
                        t_brw._browser.addheaders = []
                        del twil__headers[-1]
                        twil__headers += [('Referer', ez_link)]
                        t_brw._browser.addheaderst=twil__headers
                        t=t_brw.find_link('Download PDF')
                        # t_com.add_extra_header('Referer', t.absolute_url[0])
                        # reffe='http://library.uprm.edu:2221/S0165176511002710/1-s2.0-S0165176511002710-main.pdf?_tid=ef4c2cd0-24fb-11e6-a3f1-00000aacb361&acdnat=1464457695_083096c5266459084e056213deaf4ba7'
                        # t_com.add_extra_header('Referer', reffe)
                        # t_brw.response()
                        # t_brw.click_link(t)
                        try:t_brw.follow_link(t)
                        except:os.remove(self.cookies);return [], self.cookies, [], [], 0, self.log_out

                        # content = t_com.show()
                        html0=t_brw.result.page
                        print '@@@@@@@@@@@@@ html0 download by twill is @@@@@@@@@@@@'
                        # print html0
                        # print '@@@@@@@@@@@@@ html0 download by twill is @@@@@@@@@@@@'
                        # time.sleep(10)
                        # # link2=t_brw.result.url
                        # print '@@@@@@@@@@@@@ time.sleep(10) download by twill is @@@@@@@@@@@@'
                        # print link2
                        # print '@@@@@@@@@@@@@ time.sleep(10) download by twill is @@@@@@@@@@@@'
                        # time.sleep(10)
                        # if  not (html0[:4]=='%PDF') or html0==[] :
                        #     html2,cookies = MECAHNIZM('','',cookies=self.cookies,url=link2).speed_download(link2)
                        #     print '@@@@@@@@@@@@@ MECAHNIZM download by twill is @@@@@@@@@@@@'
                        #     print html2
                        #     print '@@@@@@@@@@@@@ MECAHNIZM download by twill is @@@@@@@@@@@@'
                        #     time.sleep(10)
                        try:t_brw.go(self.log_out['log_out'])
                        except:os.remove(self.cookies)
                        if    (html0[:4]=='%PDF' or len ( re.findall('%%EOF', html ))!=0):html=html0
                        else:html0=''
                        return html0, self.cookies, links, title, time_diff, self.log_out
                    else:
                        pass
                        # t_brw.go(self.log_out['log_out'])
        if links == '' or links == [] or links == None:
            return html, self.cookies, [], [], 0, self.log_out
        else:
            return html, self.cookies, links, title, time_diff, self.log_out

def link_tag_find0( html, base_url):
    try:
        # title=LINK().find_my_tilte(data=html,start_dash='<h1 class="article-title"',end_dash='1>',make_url=False)
        # title = LINK().find_my_tilte(data=html, start_dash='type="image/x-icon"><title>', end_dash='</title>',make_url=False)
        title = LINK().find_my_tilte(data=html, start_dash='<title>', end_dash='</title>', make_url=False)
    except:
        title = ''

    links = LINK().find_my_tilte(data=html, start_dash='<a id="pdfLink" href="', end_dash='"', make_url=True)

    if links == [] or links == '':
        links = LINK().soap_my(data=html, tag='pdfLink', attr='a', href='href', url=base_url)
    if links == '' or links == []:
        links = LINK().soap_my(data=html, tag='title="Download PDF" ', attr='a', href='href', url=base_url)
    if title == '' or title == []:
        title = LINK().soap_my(data=html, tag='class="article-title"', attr='h1', href='', url=base_url)
    if title == '' or title == []:
        title = LINK().soap_my(data=html, tag='<title>', attr='', href='', url=base_url)
    if links != []:
        pass
    return links, title


def link_tag_find01( html, base_url):
    try:
        # title=LINK().find_my_tilte(data=html,start_dash='<h1 class="article-title"',end_dash='1>',make_url=False)
        title = LINK().find_my_tilte(data=html, start_dash='type="<title>', end_dash='</title>',
                                     make_url=False)
    except:
        title = ''

    urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', html)
    print urls

    #http://stackoverflow.com/questions/6222911/how-can-i-grab-pdf-links-from-website-with-python-script
    import lxml.html, urllib2, urlparse

    # the url of the page you want to scrape
    # base_url = 'http://www.renderx.com/demos/examples.html'

    # fetch the page
    # res = urllib2.urlopen(base_url)
    #
    # # parse the response into an xml tree
    tree = lxml.html.fromstring(html)

    # construct a namespace dictionary to pass to the xpath() call
    # this lets us use regular expressions in the xpath
    ns = {'re': 'http://exslt.org/regular-expressions'}

    # iterate over all <a> tags whose href ends in ".pdf" (case-insensitive)
    for node in tree.xpath('//a[re:test(@href, "\.pdf$", "i")]', namespaces=ns):
        # print the href, joining it to the base_url
        print urlparse.urljoin(base_url, node.attrib['href'])
    #///////////////////////

    links = LINK().find_my_tilte(data=html, start_dash='<a id="pdfLink" href="', end_dash='"', make_url=True)
    m = re.search(r'<a(?: id="[^"]+")? href="http://dx.doi.org/([^"]+)"', html)
    m = re.search(r'<a(?: id="[^pdfLink"]+")? href="([^"]+)"/([^"]+".pdf")', html)
    if links == [] or links == '':
        links = LINK().soap_my(data=html, tag='pdfLink', attr='a', href='href', url=base_url)
    if links == '' or links == []:
        links = LINK().soap_my(data=html, tag='title="Download PDF" ', attr='a', href='href', url=base_url)
    if title == '' or title == []:
        title = LINK().soap_my(data=html, tag='class="article-title"', attr='h1', href='', url=base_url)
    if title == '' or title == []:
        title = LINK().soap_my(data=html, tag='<title>', attr='', href='', url=base_url)
    if links != []:
        pass
    return links, title


def link_tag_find( html, base_url):
    try:
        # title=LINK().find_my_tilte(data=html,start_dash='<h1 class="article-title"',end_dash='1>',make_url=False)
        title = LINK().find_my_tilte(data=html, start_dash='type="<title>', end_dash='</title>',
                                     make_url=False)
    except:
        title = ''

    urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', html)
    links_1 = []
    try:
        for url in urls:
            if url.endswith('.pdf') and url.split(base_url)[0]=='':
                links_1.append(url)
                print url
    except:
        pass
    if len(links_1)==1:links=links_1[0]
    elif len(links_1)>=1:links=links_1
    else :links=''

    if links == '' or links == []:
        #http://stackoverflow.com/questions/6222911/how-can-i-grab-pdf-links-from-website-with-python-script
        import lxml.html, urllib2, urlparse

        # the url of the page you want to scrape
        # base_url = 'http://www.renderx.com/demos/examples.html'

        # fetch the page
        # res = urllib2.urlopen(base_url)
        #
        # # parse the response into an xml tree
        tree = lxml.html.fromstring(html)

        # construct a namespace dictionary to pass to the xpath() call
        # this lets us use regular expressions in the xpath
        ns = {'re': 'http://exslt.org/regular-expressions'}

        # iterate over all <a> tags whose href ends in ".pdf" (case-insensitive)
        for node in tree.xpath('//a[re:test(@href, "\.pdf$", "i")]', namespaces=ns):
            # print the href, joining it to the base_url
            print urlparse.urljoin(base_url, node.attrib['href'])

            #///////////////////////

    if title == '' or title == []:
        title = LINK().find_my_tilte(data=html, start_dash='<title>', end_dash='</title>', make_url=False)
    # if links == [] or links == '':
    #     links = LINK().soap_my(data=html, tag='pdfLink', attr='a', href='href', url=base_url)
    if links == '' or links == []:
        links = LINK().soap_my(data=html, tag='title="Download PDF" ', attr='a', href='href', url=base_url)
    if title == '' or title == []:
        title = LINK().soap_my(data=html, tag='class="article-title"', attr='h1', href='', url=base_url)
    if title == '' or title == []:
        title = LINK().soap_my(data=html, tag='<title>', attr='', href='', url=base_url)

    if links != []:
        pass

    try:
                    try:
                        # title=LINK().find_my_tilte(data=html,start_dash='<h1 class="article-title"',end_dash='1>',make_url=False)
                        title=LINK().find_my_tilte(data=html,start_dash='type="image/x-icon"><title>',end_dash='</title>',make_url=False)
                    except:
                        title=''


                    links=LINK().find_my_tilte(data=html,start_dash='<a id="pdfLink" href="',end_dash='"',make_url=True)

                    if links==''or links==[]:
                        links =LINK().soap_my(data=html, tag='title="Download PDF" ', attr='a', href='href',url=base_url)

                    if links==[] or links=='':
                        links =LINK().soap_my(data=html, tag="Download PDF", attr='a', href='href',url=base_url)
                    if links==[] or links=='':
                        links=LINK().soap_my(data=html,tag='pdfLink',attr='a',href='href',url=base_url)
                    if title=='' or title==[]:
                        title=LINK().soap_my(data=html, tag='class="article-title"', attr='h1', href='',url=base_url)
                    if title=='' or title==[]:
                        title=LINK().soap_my(data=html, tag='<title>', attr='', href='',url=base_url)

                    title=LINK().find_my_tilte(data=html,start_dash='<meta property="og:title" content="',end_dash='" />',make_url=False)


                    links=LINK().find_my_tilte(data=html,start_dash='<a aria-label="Download or View Full Text as PDF" id="full-text-pdf" href='+"'",end_dash="'"+' class',make_url=True)
                    if links==[] or links=='':
                        links =LINK().soap_my(data=html, tag='title="FullText PDF"', attr='a', href='href',url=base_url)
                    if links!=[]:pass
    except:pass
    return links, title


class LINK:
    def __init__(self, url='', sites_list='configs/sites_list_pdf_tags.txt',
                 sites_list_files="configs/sites_list_files.txt",
                 site_proxy="configs//sites_proxy//", **kwargs):
        global PDF_Dir, Watermarked_PDF_Files_Dir

        fo = os.getcwd().replace('\\', '/')
        CurrentDir = os.path.dirname(os.path.realpath(__file__)).replace('\\', '/')
        Parent_Dir = os.path.abspath(os.path.join(CurrentDir, '../..')).replace('\\', '/')
        os.chdir(Parent_Dir)
        if Parent_Dir not in sys.path:
            sys.path.insert(0, Parent_Dir)
            # from  download_mozilla import web
        import proxy_checker3_all_function

        self.proxy_checker3 = proxy_checker3_all_function
        self.Mozilla_Web = web
        self.url = url
        self.sites_list = Parent_Dir.replace('\\', '/') + '/' + sites_list
        self.sites_list_files = Parent_Dir.replace('\\', '/') + '/' + sites_list_files
        self.site_proxy = site_proxy
        os.chdir(fo)

        if kwargs:
            if kwargs['PDF_Dir']:
                PDF_Dir = kwargs['PDF_Dir']
            else:
                PDF_Dir = Parent_Dir + '/PDF_Files'
            if kwargs['Watermarked_PDF_Files_Dir']:
                Watermarked_PDF_Files_Dir = kwargs['Watermarked_PDF_Files_Dir']
            else:
                Watermarked_PDF_Files_Dir = Parent_Dir + '/Watermarked_PDF_Files'
        else:
            PDF_Dir = Parent_Dir + '/PDF_Files'
            Watermarked_PDF_Files_Dir = Parent_Dir + '/Watermarked_PDF_Files'
        self.Watermarked_PDF_Dir = Watermarked_PDF_Files_Dir
        self.PDF_Files_Dir = PDF_Dir
        self.url = url

    def filename(self, pdf_url0):
        pdf_url = str(pdf_url0)

        CurrentDir = os.path.dirname(os.path.realpath(__file__)).replace('\\', '/')
        try:
            if re.findall('/', pdf_url):
                self.suffix = os.path.splitext(pdf_url)[1]
                self.file_name_decode = urllib2.unquote(pdf_url).decode('utf8').split('/')[-1]
                # self.filename = urlparse.urlsplit(pdf_url).path.split('/')[-1]
                self.filename = str(self.file_name_decode).split('&pid=')[1]
                # if self.filename.endswith('.jsp'):
                #     self.filename=(self.suffix).split('arnumber=')[1]+'.pdf'

                # self.filename=(pdf_url).split('id=')[1].split('&')[0]+'.pdf'
                # self.pdf_Folder_filename = CurrentDir + "/"+self.PDF_Files_Dir+"/" + self.filename
                # self.W_pdf_Folder_filename = CurrentDir + "/"+self.Watermarked_PDF_Dir+"/" + self.filename
                self.pdf_Folder_filename = self.PDF_Files_Dir + "/" + self.filename
                self.W_pdf_Folder_filename = self.Watermarked_PDF_Dir + "/" + self.filename
                self.chdir = CurrentDir
            else:
                self.filename = urlparse.urlsplit(pdf_url).path.split('\\')[-1]
                self.chdir = CurrentDir
                # self.pdf_Folder_filename = CurrentDir+ "/"+self.PDF_Files_Dir+"/" + self.filename
                # self.W_pdf_Folder_filename = CurrentDir + "/"+self.Watermarked_PDF_Dir+"/" + self.filename
                self.pdf_Folder_filename = self.PDF_Files_Dir + "/" + self.filename
                self.W_pdf_Folder_filename = self.Watermarked_PDF_Dir + "/" + self.filename
        except:
            if re.findall('/', pdf_url):
                self.suffix = os.path.splitext(pdf_url)[1]
                self.file_name_decode = urllib2.unquote(pdf_url).decode('utf8').split('/')[-1]
                # self.filename = urlparse.urlsplit(pdf_url).path.split('/')[-1]
                self.filename = str(self.file_name_decode).split('?_tid=')[0]
                # if self.filename.endswith('.jsp'):
                #     self.filename=(self.suffix).split('arnumber=')[1]+'.pdf'

                # self.filename=(pdf_url).split('id=')[1].split('&')[0]+'.pdf'
                # self.pdf_Folder_filename = CurrentDir + "/"+self.PDF_Files_Dir+"/" + self.filename
                # self.W_pdf_Folder_filename = CurrentDir + "/"+self.Watermarked_PDF_Dir+"/" + self.filename
                self.pdf_Folder_filename = self.PDF_Files_Dir + "/" + self.filename
                self.W_pdf_Folder_filename = self.Watermarked_PDF_Dir + "/" + self.filename
                self.chdir = CurrentDir
            else:
                self.filename = urlparse.urlsplit(pdf_url).path.split('\\')[-1]
                self.chdir = CurrentDir
                # self.pdf_Folder_filename = CurrentDir+ "/"+self.PDF_Files_Dir+"/" + self.filename
                # self.W_pdf_Folder_filename = CurrentDir + "/"+self.Watermarked_PDF_Dir+"/" + self.filename
                self.pdf_Folder_filename = self.PDF_Files_Dir + "/" + self.filename
                self.W_pdf_Folder_filename = self.Watermarked_PDF_Dir + "/" + self.filename

        return self

    def filename2(self, pdf_url0):
        pdf_url = str(pdf_url0)

        CurrentDir = os.path.dirname(os.path.realpath(__file__)).replace('\\', '/')
        if re.findall('/', pdf_url):
            self.suffix = os.path.splitext(pdf_url)[1]
            self.file_name_decode = urllib2.unquote(pdf_url).decode('utf8').split('/')[-1]
            # self.filename = urlparse.urlsplit(pdf_url).path.split('/')[-1]
            self.filename = str(self.file_name_decode).split('?_tid=')[0]
            # if self.filename.endswith('.jsp'):
            #     self.filename=(self.suffix).split('arnumber=')[1]+'.pdf'

            # self.filename=(pdf_url).split('id=')[1].split('&')[0]+'.pdf'
            # self.pdf_Folder_filename = CurrentDir + "/"+self.PDF_Files_Dir+"/" + self.filename
            # self.W_pdf_Folder_filename = CurrentDir + "/"+self.Watermarked_PDF_Dir+"/" + self.filename
            self.pdf_Folder_filename = self.PDF_Files_Dir + "/" + self.filename
            self.W_pdf_Folder_filename = self.Watermarked_PDF_Dir + "/" + self.filename
            self.chdir = CurrentDir
        else:
            self.filename = urlparse.urlsplit(pdf_url).path.split('\\')[-1]
            self.chdir = CurrentDir
            # self.pdf_Folder_filename = CurrentDir+ "/"+self.PDF_Files_Dir+"/" + self.filename
            # self.W_pdf_Folder_filename = CurrentDir + "/"+self.Watermarked_PDF_Dir+"/" + self.filename
            self.pdf_Folder_filename = self.PDF_Files_Dir + "/" + self.filename
            self.W_pdf_Folder_filename = self.Watermarked_PDF_Dir + "/" + self.filename

        return self


    def file_rd(self, path, mode='r', main_data='0'):
        # proxylist = open(path).read().split('\n')
        # print os.getcwd()
        f = open(path, mode)
        if main_data == '0':
            data = f.read().split('\n')
        else:
            data = f.read()
            # data=f.readlines()
        # print data
        f.close
        return data


    # def soap_my(self, data, tag, attr='a', href='href'):
    def soap_my(self, **kwargs):
        data = kwargs['data']
        tag = kwargs['tag']
        try:
            attr = kwargs['attr']
        except:
            attr = 'a'
        try:
            href = kwargs['href']
        except:
            href = 'href'
        try:
            url = kwargs['url']
        except:
            url = "http://" + urlparse2(self.url).hostname


        # from BeautifulSoup import BeautifulSoup
        # import re

        # site = urlparse2(self.url).hostname
        soup = BeautifulSoup(data)
        ###################
        links = soup.findAll(attr, href == True)
        # text=soup.findall('<h1>' ,text=True)
        # print links
        try:
            if links == []:
                links = soup.findAll(attr, href == True)
        except:
            pass
        done = 0
        for everytext in links:

            if re.findall(tag, str(everytext)):
                print " link url finded for downloading...\n\t%s" % everytext
                # print everytext
                if len(href) != 0:
                    if not (re.findall('www', everytext[href]) or re.findall('http://', everytext[href])):
                        f_nmae = urlparse.urljoin(url, everytext[href])

                    else:
                        f_nmae = everytext[href]
                    print unicode(f_nmae)
                    return f_nmae
                else:
                    text = ''.join(everytext.findAll(text=True))
                    data = text.strip()
                    done = 1
                    if len(text) == 0:
                        f_nmae = urlparse.urljoin(url, everytext[href])
                        text = f_nmae
                    return str(text)

                    ###############
        if done == 0:
            link = []
            return link

    def find_my_tilte(self, **kwargs):
        data = kwargs['data']
        start_dash = kwargs['start_dash']
        end_dash = kwargs['end_dash']
        try:
            make_url = kwargs['make_url']
            url = "http://" + urlparse2(self.url).hostname

        except:
            make_url = False
        try:
            revers = kwargs['reverce']
        except:
            revers = False

        # data_lowered = data.lower();
        if revers == False:
            begin = data.find(start_dash)
            end = data[begin + len(start_dash):].find(end_dash) + begin + len(start_dash)
        else:
            end = data.find(end_dash)
            begin = data[:end].rfind(start_dash)
        if begin == -1 or end == -1:
            return []
        else:
            # Find in the original html
            f_nmae = data[begin + len(start_dash):end].strip()
            if not (re.findall('www', f_nmae) or re.findall('http://', f_nmae)) and make_url == True:
                f_nmae = urlparse.urljoin(url, f_nmae)
                print " link url finded for downloading...\n\t%s" % unicode(f_nmae)
            else:
                print " link target  finded is ...\n\t%s" % f_nmae

            return f_nmae


    def dowload_basePr_userpass_link(self, url, pr_h, user_pass_h, **kwargs):
        try:
            if kwargs['cookies']:
                cookies = kwargs['cookies']
            else:
                cookies = ''
            try:
                if kwargs['piece_size']:
                    piece_size = kwargs['piece_size']
                else:
                    piece_size = 1024 * 20
            except:
                piece_size = 1024 * 20
            web = self.Mozilla_Web

            if len(user_pass_h) != 0: #user_pass_h !='' or

                # html,pr,upss,cookies=web().download(url,pr_h,user_pass_h,cookies=cookies);mech=0
                # or by mechanizm method
                html,pr,upss,cookies=web().download_mechanism(url,pr_h,user_pass_h,cookies=cookies);mech=1
                # html, pr, upss, cookies = web().download_mechanism_link(url, pr_h, user_pass_h, cookies=cookies,
                #                                                         piece_size=piece_size)
                # mech = 1


            else:

                # html,pr,upss,cookies=web().download(url,pr_h,cookies=cookies);mech=0;
                # # or by mechanizm method
                html,pr,upss,cookies=web().download_mechanism(url,pr_h,cookies=cookies);mech=1

                # html, pr, upss, cookies = web().download_mechanism_link(url, pr_h, cookies=cookies,piece_size=piece_size)
                # # mech = 1

            if html==[] or html=='':
                pass #frontpage=self.twill_download( url, cookies,pr_h)

        except:
            html = []
            link=[]
            pr = []
            upss = []
            cookies = ''
            mech = 0
            print "we cant dowload beacuse of invalid tag or invalid proxy line 620" + "\n"
        responce = {
            'html': html,
            'proxy': pr,
            'user_pass': upss,
            'cookies': cookies,
            'mechanizm': mech,
        }

        return responce

    def dowload_basePr_userpass(self, url, pr_h, user_pass_h, **kwargs):
        try:
            if kwargs['cookies']:
                cookies = kwargs['cookies']
            else:
                cookies = ''
            web = self.Mozilla_Web
            try:
                site = urlparse2(url['link']).hostname
            except:
                site = urlparse2(url).hostname
                html = []

            file = os.path.basename(os.path.realpath(__file__)).split('.pyc')[0].replace('_', '.')
            if file[-3:] == '.py':
                file = file[:-3]
            if str(site) != file:
                CurrentDir = os.path.dirname(os.path.realpath(__file__)).replace('\\', '/')
                Parent_Dir = os.path.abspath(os.path.join(CurrentDir, '../')).replace('\\', '/')
                # os.chdir(Parent_Dir)
                lg = url['log_out']
                if lg['METODE'] == '1' or  lg['METODE'] == '1+d':
                    html = twill(
                        site_list_form=Parent_Dir + '/sites_proxy/' + site + '/site_list_form.txt').twill_download(url,
                                                                                                                   cookies)
                elif lg['METODE'] == '2':
                    html, pr, upss, cookies = web().download_mechanism_link(url['link'], 'None:None', cookies=cookies);
                    mech = 1
                mech = 0
                pr = pr_h
                upss = user_pass_h
                import cookielib
            else:
                if len(user_pass_h) != 0: #user_pass_h !='' or
                    # html,pr,upss,cookies=web().download(url,pr_h,user_pass_h,cookies=cookies);mech=0

                    # # or by mechanizm method
                    # # html,pr,upss,cookies=web().download_mechanism(url,pr_h,user_pass_h,cookies=cookies);mech=1
                    html, pr, upss, cookies = web().download_mechanism_link(url, pr_h, user_pass_h, cookies=cookies);mech = 1


                else:
                    # html,pr,upss,cookies=web().download(url,pr_h,cookies=cookies);mech=0

                    # or by mechanizm method
                    # html,pr,upss,cookies=web().download_mechanism(url,pr_h,cookies=cookies);mech=1
                    html, pr, upss, cookies = web().download_mechanism_link(url, pr_h, cookies=cookies);
                    mech = 1
            try:
                os.path.isfile(html)
                file_is=1
            except:
                file_is=0


            if not (html != [] and html[:4] == '%PDF') and file_is!=1:
                if len(user_pass_h) != 0: #user_pass_h !='' or

                    html,pr,upss,cookies=web().download(url,pr_h,user_pass_h,cookies=cookies);mech=0

                    # or by mechanizm method
                    # html,pr,upss,cookies=web().download_mechanism(url,pr_h,user_pass_h,cookies=cookies);mech=1
                    # html, pr, upss, cookies = web().download_mechanism_link(url, pr_h, user_pass_h, cookies=cookies);
                    # mech = 1


                else:
                    html,pr,upss,cookies=web().download(url,pr_h,cookies=cookies);mech=0
                    # or by mechanizm method
                    # html,pr,upss,cookies=web().download_mechanism(url,pr_h,cookies=cookies);mech=1
                    # html, pr, upss, cookies = web().download_mechanism_link(url, pr_h, cookies=cookies);
                    # mech = 1

        except:
            html = []
            pr = []
            upss = []
            cookies = ''
            mech = 0
            print "we cant dowload beacuse of invalid tag or invalid proxy line 620" + "\n"
        responce = {
            'html': html,
            'proxy': pr,
            'user_pass': upss,
            'cookies': cookies,
            'mechanizm': mech,
        }
        return responce


    def get_pdf_link(self, proxy='', user_pass=''):

        url = self.url
        site = urlparse2(url).hostname
        title=''

        CurrentDir = os.path.dirname(os.path.realpath(__file__))
        Parent_Dir = os.path.abspath(os.path.join(CurrentDir, '../..')).replace('\\', '/')
        proxy_working_list = Parent_Dir + '/configs/sites_proxy/' + site + "/" + site + ".txt"
        proxy_bad_list = Parent_Dir + '/configs/sites_proxy/' + site + "/badproxylist.txt"
        if proxy == '':

            fo = os.getcwd()
            pr_h, proxy_h, user_pass_h = self.proxy_checker3.make_returning_proxy(
                "configs//sites_proxy//" + site + '//', url)
            # CurrentDir=os.path.dirname(os.path.realpath(__file__))
            # Parent_Dir=os.path.abspath(os.path.join(CurrentDir, '../..')).replace('\\','/')
            # form_n,list=self.proxy_checker3.find_form(proxy_working_list)
            form_n, list, form_av = self.proxy_checker3.find_form_av(proxy_working_list)

            os.chdir(fo)
            if not os.path.isdir(Parent_Dir + '/configs/sites_proxy/' + site):
                os.mkdir(Parent_Dir + '/configs/sites_proxy/' + site)
            form_b, list_b = self.proxy_checker3.find_form(proxy_bad_list)

        else:
            pr_h = []
            user_pass_h = []
            pr_h.append(proxy)
            user_pass_h.append(user_pass)
            # i = user_pass_h.index("")
            # del user_pass_h[i]
            try:
                i = pr_h.index("")
                del pr_h[i]
            except:
                pass

        don_flg = -1
        if pr_h != []:
            i = -1

            listhandle = self.file_rd(self.sites_list, 'r')
            file_listhandle = self.file_rd(self.sites_list_files, 'r')
            link_done = 0
            url_pdf = {}
            for j in range(0, len(pr_h)):
                form = form_n;
                form2 = form[j];
                pr_h[j] = pr_h[j].replace(' ', '')
                if don_flg != 1 and not url.endswith('.pdf') \
                    and not url.endswith('.zip') and link_done == 0:
                    time0 = time.time()

                    # from articledownloader.articledownloader import ArticleDownloader


                    if re.findall('None', pr_h[j]):
                        [html, cookies, links, title, form, time_diff, log_out] = twil_find_pdf_link(url)

                        try:
                            res = self.dowload_basePr_userpass_link(url, [], [], cookies='',
                                                                    piece_size=1024 * 3)
                            # res=self.dowload_basePr_userpass(url,pr_h[j],user_pass_h[j],cookies='')
                            html = res['html'];
                            proxy0 = res['proxy'];
                            user_pass = res['user_pass'];
                            cookies = res['cookies'];
                            mech = res['mechanizm']
                        except:
                            pass


                        # time_diff = str(round(time.time() - time0, 2))
                        if links != []:
                            try:
                                site_file = "configs//sites_proxy//"
                                if user_pass_h[j] != []:
                                    pp = pr_h[j] + '@' + user_pass_h[j]
                                else:
                                    pp = pr_h[j]

                                self.proxy_checker3.make_txt_file(site_file + site + ".txt", pp, site, time_diff)
                                self.proxy_checker3.sort_file(site_file + site + ".txt", " Rs_Time ")
                            except:
                                print 'we could not update proxy list for site:' + site + " that is worked with proxy " + pr_h[j] + '\n'
                            responce = {
                                'html': html,
                                'url': url,
                                'links': links,
                                'title': title,
                                'proxy': pr_h[j],
                                'user_pass': user_pass_h[j],
                                'cookies': cookies,
                                'mechanizm': 0,
                                'form': form,
                                'log_out': log_out
                            }
                            return responce

                    elif int(form2['Success_try']) >= int(form2['Failed_try']) + 10 or int(form2['Failed_try']) <= 10:
                        res = self.dowload_basePr_userpass_link(url, pr_h[j], user_pass_h[j], cookies='',
                                                                piece_size=1024 * 3)
                        # res=self.dowload_basePr_userpass(url,pr_h[j],user_pass_h[j],cookies='')
                        html = res['html'];
                        proxy0 = res['proxy'];
                        user_pass = res['user_pass'];
                        cookies = res['cookies'];
                        mech = res['mechanizm']
                        # print html[:4100]
                        time_diff = str(round(time.time() - time0, 2))
                        try:
                            try:
                                html2=html['file']
                            except:
                                html2=html
                            os.path.isfile(html2)
                            file_is=1
                        except:
                            file_is=0

                        if (html2!=[] and html2[:4]=='%PDF')or file_is==1 :
                            pass
                           # responce = {
                           #  'html': html,
                           #  'url': url,
                           #  'links': [],
                           #  'title': title,
                           #  'proxy': pr_h[j],
                           #  'user_pass': user_pass_h[j],
                           #  'cookies': cookies,
                           #  'mechanizm': mech}
                           # return responce
                        if ( link_done == 0 and html2 != [] or  html2[:4]=='%PDF') or  file_is==1:
                            if not ( html2[:4]=='%PDF' or  file_is==1):
                                [links, title] = link_tag_find(html2, url)
                                try:
                                    links1 = links[1]
                                except:
                                    links1=links
                                if not ((links == [] or links == None or links == '') )   :
                                    res = self.dowload_basePr_userpass_link(links1, pr_h[j], user_pass_h[j], cookies='',
                                                                piece_size=1024 * 3)
                                    html,cookies = MECAHNIZM(pr_h[j],cookies=cookies,url=url).download_pdf_br(url)
                             #      res=self.dowload_basePr_userpass(url,pr_h[j],user_pass_h[j],cookies='')
                                    html = res['html'];
                                    proxy0 = res['proxy'];
                                    user_pass = res['user_pass'];
                                    cookies = res['cookies'];
                                    mech = res['mechanizm']
                                    print html
                            else:
                                links=html['links'];
                                title=html['title'];
                                html=html['html']
                                # [links, title] = link_tag_find(html, url)
                                # links=self.url;
                                links1=links

                            #  html2, pr, upss, cookies = web().download_mechanism_link(links1, proxy0, cookies=cookies,url_reffrence=url);
                           # # download_bash_curl
                           #
                           #  frontpage, pr, upss, cookies= web().download(links1, proxy0, cookies=cookies,url_reffrence=url);
                            # try:
                            #     if os.path.isfile(html):
                            #         h=open(html)
                            #         ht=h.read()
                            #         h.close()
                            #         os.remove(html)
                            #         html=ht
                            # except:
                            #     pass



                            # links =self.soap_my(data=html, tag='FullTextPdf', attr='a', href='href',url=url)
                            # try:
                            #     title=self.find_my_tilte(data=html,start_dash='<h1 class="article-title"',end_dash='1>',make_url=False)
                            #     title=self.find_my_tilte(data=title,start_dash='">',end_dash='</h',make_url=False)
                            # except:
                            #     title=''
                            #
                            #
                            # links=self.find_my_tilte(data=html,start_dash='<a id="pdfLink" href="',end_dash='"',make_url=True)
                            #
                            #
                            # if links==''or links==[]:
                            #     links =self.soap_my(data=html, tag='title="Download PDF" ', attr='a', href='href',url=url)
                            # # if links==[] or links=='':
                            # #     # links=self.soap_my(data=html,tag='pdfLink',attr='a',href='href',url=url)
                            # if title=='' or title==[]:
                            #     title=self.soap_my(data=html, tag='class="article-title"', attr='h1', href='',url=url)
                            # if title=='' or title==[]:
                            #     title=self.soap_my(data=html, tag='<title>', attr='h1', href='',url=url)

                            # title=self.find_my_tilte(data=title,start_dash='">',end_dash='</h1>',make_url=False)



                            # if links == [] or links==None:
                            #     links =self.soap_my(data=html, tag='Full Text', attr='a', href='href',url=url)
                            # clear = lambda: os.system(['clear','cls'][os.name == 'nt']);clear()
                            # print html


                            # if links!=[] and mech!=1 :
                            #     res=self.dowload_basePr_userpass_link(url,pr_h[j],user_pass_h[j],cookies='')
                            #     html=res['html'];proxy0=res['proxy'];user_pass=res['user_pass'];cookies=res['cookies'];mech=res['mechanizm']
                            #     # try:
                            #     #     if os.path.isfile(html):
                            #     #         h=open(html)
                            #     #         ht=h.read()
                            #     #         h.close()
                            #     #         os.remove(html)
                            #     #         html=ht
                            #     # except:
                            #     #     pass
                            #
                            #     links =self.soap_my(data=html, tag='<frame src="http://ieeexplore.ieee.org', attr='frame', href='src',url=str(links))
                            #     # links2=self.soap_my(html,'<frame src="http://ieeexplore.ieee.org','frame','src')
                            # links=links2
                            try:
                                 os.path.isfile(html)
                                 file_is=1
                            except:
                                file_is=0
                            if ((links == [] or links == None or links == '') )   :
                                pass
                            else :
                              if  html[:4]=='%PDF' or  file_is==1:
                                link_done = 1
                                print '---------------we found Proper link which is :------------\n' + str(links) + \
                                      '\n ----with proxy-------\n' + str(pr_h[j]) + ':' + str(user_pass_h[j])
                                print '----------------- Link Found -------------------------'
                                try:
                                    site_file = "configs//sites_proxy//"
                                    if user_pass_h[j] != []:
                                        pp = pr_h[j] + '@' + user_pass_h[j]
                                    else:
                                        pp = pr_h[j]

                                    # form,list=self.proxy_checker3.find_form(site_file + site + ".txt")
                                    # for i in range(0,len(form)):
                                    #     form2=form[i]
                                    if True:
                                        i = j
                                        if re.findall(pr_h[j], form2['ip']):
                                            if re.findall('Success_try:', list[i]):
                                                pattern = [list[i].split('Failed_try:')[0] + 'Failed_try:' + form2[
                                                    'Failed_try'],
                                                           list[i].split('Success_try:')[0] + 'Success_try:' + form2[
                                                               'Success_try'],
                                                           list[i].split('Rs_Time')[0] + 'Rs_Time ' + form2['time']
                                                ];
                                                new_pattenr = [list[i].split('Failed_try:')[0] + 'Failed_try:' + str(
                                                    int(form2['Failed_try'])),
                                                               list[i].split('Success_try:')[0] + 'Success_try:' + str(
                                                                   int((form2['Success_try'])) + 1),
                                                               list[i].split('Rs_Time')[0] + 'Rs_Time ' + time_diff
                                                ]
                                            else:
                                                pattern = [list[i].replace('\r', '').replace('\n', ''),
                                                           list[i].replace('\r', '').replace('\n', '')
                                                ];
                                                new_pattenr = [list[i].replace('\r', '').replace('\n', ''),
                                                               list[i].split('\n')[0].replace('\r', '').split(
                                                                   'Rs_Time')[
                                                                   0] + ' Rs_Time ' + time_diff + ' Success_try:' + str(
                                                                   int(form2[
                                                                       'Success_try']) + 1) + ' Failed_try:' + str(
                                                                   int(form2['Failed_try']))
                                                ]

                                            if int(form2['Success_try'])+ 30 >= int(form2['Failed_try']) :
                                                self.proxy_checker3.replace(proxy_working_list, pattern, new_pattenr)


                                                # self.proxy_checker3.make_txt_file(site_file + site + ".txt", pp, site, time_diff)
                                        # self.proxy_checker3.sort_file(proxy_working_list, " Rs_Time ")
                                    # self.proxy_checker3.sort_file(proxy_working_list, "Success_try:","Failed_try:",
                                    #                               sort_type='reversed')
                                    break
                                except:
                                    print 'we could not update proxy list for site:' + site + " that is worked with proxy " +pr_h[j] + '\n'

                                break

                                # for line in listhandle:
                                #     if re.findall(site, line) and link_done == 0 and (not re.findall("#", line.split("TAG:")[0])) :
                                #         if re.findall("TAG1:", line):
                                #             try:
                                #                 Tag = line.split("TAG1:")[1].split("---")[0]
                                #                 Tag=Tag.replace("+++",'')
                                #                 atrr = line.split("Attr1:")[1].split("---")[0]
                                #                 atrr=atrr.replace("+++",'')
                                #                 href=line.split('Href1:')[1].split("---")[0]
                                #                 href=href.replace("+++",'')
                                #                 links =self.soap_my(data=html, tag=Tag, attr=atrr, href=href,url=url)
                                #                 # links = self.soap_my(html, Tag, atrr,href)
                                #                 if links != [] and link_done!=None and mech!=1:
                                #                     try:
                                #                         Tag = line.split("TAG2:")[1].split("---")[0]
                                #                         Tag=Tag.replace("---",'').replace("+++",'')
                                #
                                #                         atrr = line.split("Attr2:")[1].split("---")[0]
                                #                         atrr=atrr.replace('---','').replace("+++",'')
                                #                         href=line.split('Href2:')[1].split("---")[0]
                                #                         href=href.replace("+++",'')
                                #                         res=self.dowload_basePr_userpass_link(url,pr_h[j],user_pass_h[j],cookies='')
                                #                         html=res['html'];proxy0=res['proxy'];user_pass=res['user_pass'];cookies=res['cookies'];mech=res['mechanizm']
                                #                         # links = self.soap_my(html, Tag, atrr,href)
                                #                     except:pass
                                #                     # [html,proxy0,user_pass]=self.dowload_basePr_userpass(links,pr_h[j],user_pass_h[j])
                                #                     # links =self.soap_my(data=html, tag=Tag, attr=atrr, href=href,url=url)
                                #                     # links = self.soap_my(html, Tag, atrr,href)
                                #                     if links != [] or links!=None:
                                #                         link_done = 1
                                #                         print '---------------we found Proper link which is :------------\n'+str(links)+ \
                                #                               '\n ----with proxy-------\n'+str(pr_h[j])+':'+str(user_pass_h[j])
                                #                         print '----------------- Link Found -------------------------'
                                #                         return links,pr_h[j],user_pass_h[j]
                                #
                                #             except:
                                #                 pass



                        elif link_done == 1:
                            print "<li><a>tag found</a></li>"
                            print links
                            break
                        elif link_done == 0:
                            # CurrentDir=os.path.dirname(os.path.realpath(__file__))
                            # Parent_Dir=os.path.abspath(os.path.join(CurrentDir, '../..')).replace('\\','/')
                            # if not os.path.isdir(Parent_Dir+'/configs/sites_proxy/'+site):
                            #     os.mkdir(Parent_Dir+'/configs/sites_proxy/'+site)
                            time_diff = str(round(time.time() - time0, 2))

                            # if len(user_pass)!=0:
                            #     self.proxy_checker3.make_txt_file(Parent_Dir+'/configs/sites_proxy/'+site+"/badproxylist.txt", str(pr_h[j])+'@'+str(user_pass_h[j]), site, time_diff)
                            # else:
                            #     pass
                            #     # self.proxy_checker3.make_txt_file(Parent_Dir+'/configs/sites_proxy/'+site+"/badproxylist.txt", str(pr_h[j]), site, time_diff)
                            if True: #badproxylist.txt
                                done = 0
                                for i in range(0, len(form_b)):
                                    form3 = form_b[i]
                                    if re.findall(pr_h[j], form2['ip']):
                                        if re.findall('Success_try:', list_b[i]):
                                            pattern = [
                                                list_b[i].split('Failed_try:')[0] + 'Failed_try:' + form3['Failed_try'],
                                                list_b[i].split('Success_try:')[0] + 'Success_try:' + form3[
                                                    'Success_try'],
                                                list_b[i].split('Rs_Time ')[0] + 'Rs_Time ' + form3['time']
                                            ];
                                            new_pattenr = [list_b[i].split('Failed_try:')[0] + 'Failed_try:' + str(
                                                int(form3['Failed_try']) + 1),
                                                           list_b[i].split('Success_try:')[0] + 'Success_try:' + form3[
                                                               'Success_try'],
                                                           list_b[i].split('Rs_Time ')[0] + 'Rs_Time ' + time_diff
                                            ]
                                        else:
                                            pattern = [list_b[i].replace('\r', '').replace('\n', ''),
                                                       list_b[i].replace('\r', '').replace('\n', '')
                                            ];
                                            new_pattenr = [list_b[i].replace('\r', '').replace('\n', ''),
                                                           list_b[i].split('\n')[0].replace('\r', '').split(
                                                               ' Rs_Time ')[
                                                               0] + 'Rs_Time ' + time_diff + ' Success_try:' + form3[
                                                               'Success_try'] + ' Failed_try:' + str(
                                                               int(form3['Failed_try']) + 1)
                                            ]

                                        self.proxy_checker3.replace(
                                            Parent_Dir + '/configs/sites_proxy/' + site + "/badproxylist.txt", pattern,
                                            new_pattenr)
                                        don = 1
                                        break
                                if don == 0:
                                    if len(user_pass) != 0:
                                        self.proxy_checker3.make_txt_file(
                                            Parent_Dir + '/configs/sites_proxy/' + site + "/badproxylist.txt",
                                            str(pr_h[j]) + '@' + str(user_pass_h[j]), site, time_diff)
                                    else:
                                        self.proxy_checker3.make_txt_file(
                                            Parent_Dir + '/configs/sites_proxy/' + site + "/badproxylist.txt",
                                            str(pr_h[j]), site, time_diff)

                                # form,list=self.proxy_checker3.find_form(Parent_Dir+'/configs/sites_proxy/'+site+"/"+site+".txt")
                                # for i in range(0,len(form)):
                                #     form2=form[i]
                                if True:#proxy_working_list
                                    if re.findall(form2['ip'], pr_h[j]):
                                        i = j
                                        if re.findall('Success_try:', list[i]):
                                            pattern = [
                                                list[i].split('Failed_try:')[0] + 'Failed_try:' + form2['Failed_try'],
                                                list[i].split('Success_try:')[0] + 'Success_try:' + form2[
                                                    'Success_try'],
                                                list[i].split('Rs_Time ')[0] + 'Rs_Time ' + form2['time']
                                            ];
                                            new_pattenr = [list[i].split('Failed_try:')[0] + 'Failed_try:' + str(
                                                int(form2['Failed_try']) + 1),
                                                           list[i].split('Success_try:')[0] + 'Success_try:' + form2[
                                                               'Success_try'],
                                                           list[i].split('Rs_Time ')[0] + 'Rs_Time ' + time_diff
                                            ]
                                        else:
                                            pattern = [list[i].replace('\r', '').replace('\n', ''),
                                                       list[i].replace('\r', '').replace('\n', '')
                                            ];
                                            new_pattenr = [list[i].replace('\r', '').replace('\n', ''),
                                                           list[i].split('\n')[0].replace('\r', '').split('Rs_Time ')[
                                                               0] + 'Rs_Time ' + time_diff + ' Success_try:' + form2[
                                                               'Success_try'] + ' Failed_try:' + str(
                                                               int(form2['Failed_try']) + 1)
                                            ]

                                        self.proxy_checker3.replace(
                                            Parent_Dir + '/configs/sites_proxy/' + site + "/" + site + ".txt", pattern,
                                            new_pattenr)
                                        # break


                elif url != [] or (url.endswith('.pdf') or url.endswith('.zip')):

                    cookies = ''
                    responce = {
                        'html': html,
                        'url': url,
                        'links': url,
                        'title': '',
                        'proxy': '',
                        'user_pass': '',
                        'cookies': cookies,
                        'mechanizm': mech,
                    }
                    return responce

                    # return url,'','',cookies

            if link_done == 0:
                links = []
                pr_h[j] = []
                user_pass_h[j] = []
                title = ''
                cookies = ''
                mech = 0
                print "we couldnt find link beacuase of no proxy is able to download .find good proxy over internet"
            responce = {
                'html': html,
                'url': url,
                'links': links,
                'title': title,
                'proxy': pr_h[j],
                'user_pass': user_pass_h[j],
                'cookies': cookies,
                'mechanizm': mech,
            }
            return responce


            # return links,pr_h[j],user_pass_h[j],cookies,

        else: # pr_h[j]=[] there is no trusted proxy for it
            res = self.dowload_basePr_userpass_link(url, "None:None", [], cookies='')
            html = res['html'];
            proxy0 = res['proxy'];
            user_pass = res['user_pass'];
            cookies = res['cookies'];
            mech = res['mechanizm']
            # [html,proxy0,user_pass,cookies]=self.dowload_basePr_userpass_link(url,"None:None",[],cookies='')
            links = self.soap_my(data=html, tag='title="FullText PDF"', attr='a', href='href', url=url)
            title = self.soap_my(data=html, tag='class="mediumb-text" style="margin-top:0px; margin-bottom:0px;"',
                                 attr='h1', href='href', url=url)
            # if links==[]:
            #     res=self.dowload_basePr_userpass_link(links,"None:None",[],cookies=cookies)
            #     html=res['html'];proxy0=res['proxy'];user_pass=res['user_pass'];cookies=res['cookies'];mech=res['mechanizm']
            #     # [html,proxy0,user_pass,cookies]=self.dowload_basePr_userpass_link(links,"None:None",[],cookies=cookies)
            #     links2=LINK(links).soap_my(html,'<frame src="http://ieeexplore.ieee.org','frame','src')
            #     link=links2
            if links == [] or links == None or links == '':
                print'there is no trusted proxy for downloading it'
            else:
                link_done = 1
            responce = {
                'html': html,
                'url': url,
                'links': links,
                'title': title,
                'proxy': [],
                'user_pass': [],
                'cookies': cookies,
                'mechanizm': mech,
            }
            return responce
            # return links,[],[],cookies

    def get_pdf_link_two_state(self, proxy='', user_pass='',tag='', attr='', href=''):

        url = self.url
        site = urlparse2(url).hostname

        CurrentDir = os.path.dirname(os.path.realpath(__file__))
        Parent_Dir = os.path.abspath(os.path.join(CurrentDir, '../..')).replace('\\', '/')
        proxy_working_list = Parent_Dir + '/configs/sites_proxy/' + site + "/" + site + ".txt"
        proxy_bad_list = Parent_Dir + '/configs/sites_proxy/' + site + "/badproxylist.txt"
        if proxy == '':

            fo = os.getcwd()
            pr_h, proxy_h, user_pass_h = self.proxy_checker3.make_returning_proxy(
                "configs//sites_proxy//" + site + '//', url)
            # CurrentDir=os.path.dirname(os.path.realpath(__file__))
            # Parent_Dir=os.path.abspath(os.path.join(CurrentDir, '../..')).replace('\\','/')
            # form_n,list=self.proxy_checker3.find_form(proxy_working_list)
            form_n, list, form_av = self.proxy_checker3.find_form_av(proxy_working_list)

            os.chdir(fo)
            if not os.path.isdir(Parent_Dir + '/configs/sites_proxy/' + site):
                os.mkdir(Parent_Dir + '/configs/sites_proxy/' + site)
            form_b, list_b = self.proxy_checker3.find_form(proxy_bad_list)

        else:
            pr_h = []
            user_pass_h = []
            pr_h.append(proxy)
            user_pass_h.append(user_pass)
            # i = user_pass_h.index("")
            # del user_pass_h[i]
            try:
                i = pr_h.index("")
                del pr_h[i]
            except:
                pass

        don_flg = -1
        if pr_h != []:
            i = -1

            listhandle = self.file_rd(self.sites_list, 'r')
            file_listhandle = self.file_rd(self.sites_list_files, 'r')
            link_done = 0
            url_pdf = {}
            for j in range(0, len(pr_h)):
                form = [];#form_n;
                form2 =[];# form[j];
                pr_h[j] = pr_h[j].replace(' ', '')
                if don_flg != 1 and not url.endswith('.pdf') \
                    and not url.endswith('.zip') and link_done == 0:
                    time0 = time.time()

                    # from articledownloader.articledownloader import ArticleDownloader


                    if re.findall('None', pr_h[j]):
                        [html, cookies, links, title, form, time_diff, log_out] = twil_find_pdf_link(url)
                        # time_diff = str(round(time.time() - time0, 2))
                        if links != []:
                            try:
                                site_file = "configs//sites_proxy//"
                                if user_pass_h[j] != []:
                                    pp = pr_h[j] + '@' + user_pass_h[j]
                                else:
                                    pp = pr_h[j]

                                self.proxy_checker3.make_txt_file(site_file + site + ".txt", pp, site, time_diff)
                                self.proxy_checker3.sort_file(site_file + site + ".txt", " Rs_Time ")
                            except:
                                print 'we could not update proxy list for site:' + site + " that is worked with proxy " + pr_h[j] + '\n'
                            responce = {
                                'html': html,
                                'url': url,
                                'links': links,
                                'title': title,
                                'proxy': pr_h[j],
                                'user_pass': user_pass_h[j],
                                'cookies': cookies,
                                'mechanizm': 0,
                                'form': form,
                                'log_out': log_out
                            }
                            return responce

                    elif True:# int(form2['Success_try']) >= int(form2['Failed_try']) + 10 or int(form2['Failed_try']) <= 10:

                        res2 = self.dowload_basePr_userpass_link(url, pr_h[j], user_pass_h[j], cookies='',
                                                                piece_size=1024 * 3)
                        res = self.dowload_basePr_userpass_link(url, '', '', cookies='',
                                                                piece_size=1024 * 3)
                        # res=self.dowload_basePr_userpass(url,pr_h[j],user_pass_h[j],cookies='')
                        html = res['html'];
                        html2 = res2['html'];
                        proxy0 = res['proxy'];
                        user_pass = res['user_pass'];
                        cookies = res['cookies'];
                        mech = res['mechanizm']
                        # print html[:4100]
                        time_diff = str(round(time.time() - time0, 2))

                        article_number=self.find_my_tilte(data=html,start_dash='<strong>Publications:',end_dash='</strong>',make_url=False)
                        article_number2=self.find_my_tilte(data=html2,start_dash='<strong>Publications:',end_dash='</strong>',make_url=False)



                        if link_done == 0 and html2 != [] and int(article_number2) > int(article_number):
                            #[links, title] = link_tag_find(html, url)
                            # try:
                            #     if os.path.isfile(html):
                            #         h=open(html)
                            #         ht=h.read()
                            #         h.close()
                            #         os.remove(html)
                            #         html=ht
                            # except:
                            #     pass



                            # links =self.soap_my(data=html, tag='FullTextPdf', attr='a', href='href',url=url)
                            # try:
                            #     title=self.find_my_tilte(data=html,start_dash='<h1 class="article-title"',end_dash='1>',make_url=False)
                            #     title=self.find_my_tilte(data=title,start_dash='">',end_dash='</h',make_url=False)
                            # except:
                            #     title=''
                            #
                            #
                            # links=self.find_my_tilte(data=html,start_dash='<a id="pdfLink" href="',end_dash='"',make_url=True)
                            #
                            #
                            # if links==''or links==[]:
                            #     links =self.soap_my(data=html, tag='title="Download PDF" ', attr='a', href='href',url=url)
                            # # if links==[] or links=='':
                            # #     # links=self.soap_my(data=html,tag='pdfLink',attr='a',href='href',url=url)
                            # if title=='' or title==[]:
                            #     title=self.soap_my(data=html, tag='class="article-title"', attr='h1', href='',url=url)
                            # if title=='' or title==[]:
                            #     title=self.soap_my(data=html, tag='<title>', attr='h1', href='',url=url)

                            # title=self.find_my_tilte(data=title,start_dash='">',end_dash='</h1>',make_url=False)



                            # if links == [] or links==None:
                            #     links =self.soap_my(data=html, tag='Full Text', attr='a', href='href',url=url)
                            # clear = lambda: os.system(['clear','cls'][os.name == 'nt']);clear()
                            # print html


                            # if links!=[] and mech!=1 :
                            #     res=self.dowload_basePr_userpass_link(url,pr_h[j],user_pass_h[j],cookies='')
                            #     html=res['html'];proxy0=res['proxy'];user_pass=res['user_pass'];cookies=res['cookies'];mech=res['mechanizm']
                            #     # try:
                            #     #     if os.path.isfile(html):
                            #     #         h=open(html)
                            #     #         ht=h.read()
                            #     #         h.close()
                            #     #         os.remove(html)
                            #     #         html=ht
                            #     # except:
                            #     #     pass
                            #
                            #     links =self.soap_my(data=html, tag='<frame src="http://ieeexplore.ieee.org', attr='frame', href='src',url=str(links))
                            #     # links2=self.soap_my(html,'<frame src="http://ieeexplore.ieee.org','frame','src')
                            # links=links2
                            if links == [] or links == None or links == '':
                                pass
                            if int(article_number2) > int(article_number):
                                link_done = 1
                                print '---------------we found Proper link which is :------------\n' + str(links) + \
                                      '\n ----with proxy-------\n' + str(pr_h[j]) + ':' + str(user_pass_h[j])
                                print '----------------- Link Found -------------------------'
                                try:
                                    site_file = "configs//sites_proxy//"
                                    if user_pass_h[j] != []:
                                        pp = pr_h[j] + '@' + user_pass_h[j]
                                    else:
                                        pp = pr_h[j]

                                    # form,list=self.proxy_checker3.find_form(site_file + site + ".txt")
                                    # for i in range(0,len(form)):
                                    #     form2=form[i]
                                    if True:
                                        i = j
                                        if re.findall(pr_h[j], form2['ip']):
                                            if re.findall('Success_try:', list[i]):
                                                pattern = [list[i].split('Failed_try:')[0] + 'Failed_try:' + form2[
                                                    'Failed_try'],
                                                           list[i].split('Success_try:')[0] + 'Success_try:' + form2[
                                                               'Success_try'],
                                                           list[i].split('Rs_Time')[0] + 'Rs_Time ' + form2['time']
                                                ];
                                                new_pattenr = [list[i].split('Failed_try:')[0] + 'Failed_try:' + str(
                                                    int(form2['Failed_try'])),
                                                               list[i].split('Success_try:')[0] + 'Success_try:' + str(
                                                                   int((form2['Success_try'])) + 1),
                                                               list[i].split('Rs_Time')[0] + 'Rs_Time ' + time_diff
                                                ]
                                            else:
                                                pattern = [list[i].replace('\r', '').replace('\n', ''),
                                                           list[i].replace('\r', '').replace('\n', '')
                                                ];
                                                new_pattenr = [list[i].replace('\r', '').replace('\n', ''),
                                                               list[i].split('\n')[0].replace('\r', '').split(
                                                                   'Rs_Time')[
                                                                   0] + ' Rs_Time ' + time_diff + ' Success_try:' + str(
                                                                   int(form2[
                                                                       'Success_try']) + 1) + ' Failed_try:' + str(
                                                                   int(form2['Failed_try']))
                                                ]

                                            if int(form2['Success_try']) >= int(form2['Failed_try']) + 30:
                                                self.proxy_checker3.replace(proxy_working_list, pattern, new_pattenr)


                                                # self.proxy_checker3.make_txt_file(site_file + site + ".txt", pp, site, time_diff)
                                        # self.proxy_checker3.sort_file(proxy_working_list, " Rs_Time ")
                                    self.proxy_checker3.sort_file(proxy_working_list, " Success_try:",
                                                                  sort_type='reversed')
                                    break
                                except:
                                    print 'we could not update proxy list for site:' + site + " that is worked with proxy " +pr_h[j] + '\n'

                                break

                                # for line in listhandle:
                                #     if re.findall(site, line) and link_done == 0 and (not re.findall("#", line.split("TAG:")[0])) :
                                #         if re.findall("TAG1:", line):
                                #             try:
                                #                 Tag = line.split("TAG1:")[1].split("---")[0]
                                #                 Tag=Tag.replace("+++",'')
                                #                 atrr = line.split("Attr1:")[1].split("---")[0]
                                #                 atrr=atrr.replace("+++",'')
                                #                 href=line.split('Href1:')[1].split("---")[0]
                                #                 href=href.replace("+++",'')
                                #                 links =self.soap_my(data=html, tag=Tag, attr=atrr, href=href,url=url)
                                #                 # links = self.soap_my(html, Tag, atrr,href)
                                #                 if links != [] and link_done!=None and mech!=1:
                                #                     try:
                                #                         Tag = line.split("TAG2:")[1].split("---")[0]
                                #                         Tag=Tag.replace("---",'').replace("+++",'')
                                #
                                #                         atrr = line.split("Attr2:")[1].split("---")[0]
                                #                         atrr=atrr.replace('---','').replace("+++",'')
                                #                         href=line.split('Href2:')[1].split("---")[0]
                                #                         href=href.replace("+++",'')
                                #                         res=self.dowload_basePr_userpass_link(url,pr_h[j],user_pass_h[j],cookies='')
                                #                         html=res['html'];proxy0=res['proxy'];user_pass=res['user_pass'];cookies=res['cookies'];mech=res['mechanizm']
                                #                         # links = self.soap_my(html, Tag, atrr,href)
                                #                     except:pass
                                #                     # [html,proxy0,user_pass]=self.dowload_basePr_userpass(links,pr_h[j],user_pass_h[j])
                                #                     # links =self.soap_my(data=html, tag=Tag, attr=atrr, href=href,url=url)
                                #                     # links = self.soap_my(html, Tag, atrr,href)
                                #                     if links != [] or links!=None:
                                #                         link_done = 1
                                #                         print '---------------we found Proper link which is :------------\n'+str(links)+ \
                                #                               '\n ----with proxy-------\n'+str(pr_h[j])+':'+str(user_pass_h[j])
                                #                         print '----------------- Link Found -------------------------'
                                #                         return links,pr_h[j],user_pass_h[j]
                                #
                                #             except:
                                #                 pass



                        elif link_done == 1:
                            print "<li><a>tag found</a></li>"
                            print links
                            break
                        elif link_done == 0:
                            # CurrentDir=os.path.dirname(os.path.realpath(__file__))
                            # Parent_Dir=os.path.abspath(os.path.join(CurrentDir, '../..')).replace('\\','/')
                            # if not os.path.isdir(Parent_Dir+'/configs/sites_proxy/'+site):
                            #     os.mkdir(Parent_Dir+'/configs/sites_proxy/'+site)
                            time_diff = str(round(time.time() - time0, 2))

                            # if len(user_pass)!=0:
                            #     self.proxy_checker3.make_txt_file(Parent_Dir+'/configs/sites_proxy/'+site+"/badproxylist.txt", str(pr_h[j])+'@'+str(user_pass_h[j]), site, time_diff)
                            # else:
                            #     pass
                            #     # self.proxy_checker3.make_txt_file(Parent_Dir+'/configs/sites_proxy/'+site+"/badproxylist.txt", str(pr_h[j]), site, time_diff)
                            if True:
                                done = 0
                                if done == 0:
                                    if len(user_pass) != 0:
                                        self.proxy_checker3.make_txt_file(
                                            Parent_Dir + '/configs/sites_proxy/' + site + "/badproxylist.txt",
                                            str(pr_h[j]) + '@' + str(user_pass_h[j]), site, time_diff)
                                    else:
                                        self.proxy_checker3.make_txt_file(
                                            Parent_Dir + '/configs/sites_proxy/' + site + "/badproxylist.txt",
                                            str(pr_h[j]), site, time_diff)

                                # form,list=self.proxy_checker3.find_form(Parent_Dir+'/configs/sites_proxy/'+site+"/"+site+".txt")
                                # for i in range(0,len(form)):
                                #     form2=form[i]
                                if False:
                                    if re.findall(form2['ip'], pr_h[j]):
                                        i = j
                                        if re.findall('Success_try:', list[i]):
                                            pattern = [
                                                list[i].split('Failed_try:')[0] + 'Failed_try:' + form2['Failed_try'],
                                                list[i].split('Success_try:')[0] + 'Success_try:' + form2[
                                                    'Success_try'],
                                                list[i].split('Rs_Time ')[0] + 'Rs_Time ' + form2['time']
                                            ];
                                            new_pattenr = [list[i].split('Failed_try:')[0] + 'Failed_try:' + str(
                                                int(form2['Failed_try']) + 1),
                                                           list[i].split('Success_try:')[0] + 'Success_try:' + form2[
                                                               'Success_try'],
                                                           list[i].split('Rs_Time ')[0] + 'Rs_Time ' + time_diff
                                            ]
                                        else:
                                            pattern = [list[i].replace('\r', '').replace('\n', ''),
                                                       list[i].replace('\r', '').replace('\n', '')
                                            ];
                                            new_pattenr = [list[i].replace('\r', '').replace('\n', ''),
                                                           list[i].split('\n')[0].replace('\r', '').split('Rs_Time ')[
                                                               0] + 'Rs_Time ' + time_diff + ' Success_try:' + form2[
                                                               'Success_try'] + ' Failed_try:' + str(
                                                               int(form2['Failed_try']) + 1)
                                            ]

                                        self.proxy_checker3.replace(
                                            Parent_Dir + '/configs/sites_proxy/' + site + "/" + site + ".txt", pattern,
                                            new_pattenr)
                                        # break


                elif url != [] or (url.endswith('.pdf') or url.endswith('.zip')):

                    cookies = ''
                    responce = {
                        'html': html,
                        'url': url,
                        'links': url,
                        'title': '',
                        'proxy': '',
                        'user_pass': '',
                        'cookies': cookies,
                        'mechanizm': mech,
                    }
                    return responce

                    # return url,'','',cookies

            if link_done == 0:
                links = []
                pr_h[j] = []
                user_pass_h[j] = []
                title = ''
                cookies = ''
                mech = 0
                print "we couldnt find link beacuase of no proxy is able to download .find good proxy over internet"
            responce = {
                'html': html,
                'url': url,
                'links': links,
                'title': title,
                'proxy': pr_h[j],
                'user_pass': user_pass_h[j],
                'cookies': cookies,
                'mechanizm': mech,
            }
            return responce


            # return links,pr_h[j],user_pass_h[j],cookies,

        else: # pr_h[j]=[] there is no trusted proxy for it
            res = self.dowload_basePr_userpass_link(url, "None:None", [], cookies='')
            html = res['html'];
            proxy0 = res['proxy'];
            user_pass = res['user_pass'];
            cookies = res['cookies'];
            mech = res['mechanizm']
            # [html,proxy0,user_pass,cookies]=self.dowload_basePr_userpass_link(url,"None:None",[],cookies='')
            links = self.soap_my(data=html, tag='title="FullText PDF"', attr='a', href='href', url=url)
            title = self.soap_my(data=html, tag='class="mediumb-text" style="margin-top:0px; margin-bottom:0px;"',
                                 attr='h1', href='href', url=url)
            # if links==[]:
            #     res=self.dowload_basePr_userpass_link(links,"None:None",[],cookies=cookies)
            #     html=res['html'];proxy0=res['proxy'];user_pass=res['user_pass'];cookies=res['cookies'];mech=res['mechanizm']
            #     # [html,proxy0,user_pass,cookies]=self.dowload_basePr_userpass_link(links,"None:None",[],cookies=cookies)
            #     links2=LINK(links).soap_my(html,'<frame src="http://ieeexplore.ieee.org','frame','src')
            #     link=links2
            if links == [] or links == None or links == '':
                print'there is no trusted proxy for downloading it'
            else:
                link_done = 1
            responce = {
                'html': html,
                'url': url,
                'links': links,
                'title': title,
                'proxy': [],
                'user_pass': [],
                'cookies': cookies,
                'mechanizm': mech,
            }
            return responce
            # return links,[],[],cookies

    def curl_download(self, url, cookies='',proxy=''):
        # self.url="%(ezproxy_host)s"%form_data
        # self.database_link="%(database_link)s"%form_data
        # self.username="%(user)s"%form_data
        # self.password="%(pass)s"%form_data
        # self.user_tag="%(user_tag)s"%form_data
        # self.pass_tag="%(pass_tag)s"%form_data
        # self.Form_id="%(Form_id)s"%form_data
        # self.submit_tag_name="%(submit_tag_name)s"%form_data
        # self.submit_tag_value="%(submit_tag_value)s"%form_data
        # self.Form_Type="%(Form_Type)s"%form_data
        # self.log_done="%(Log_test)s"%form_data
        link = url;
        # lg = url['log_out'];
        # url_logout = lg['log_out'];
        # ez_link = lg['ez_link']
        # twil__headers = lg['headers']

        if proxy!='':
            import subprocess
            #phantomjs --webdriver=8080 --webdriver-selenium-grid-hub=http://127.0.0.1:4444
            #phantomjs --webdriver=8080 --webdriver-selenium-grid-hub=http://127.2.25.129:4444
            #st='phantomjs --webdriver=8080 --webdriver-selenium-grid-hub=http://'+ip+':4444'
            # st='export http_proxy="http://'+proxy+'"'
            st='export HTTP_PROXY='+proxy
            awk_sort = subprocess.Popen( [st ], stdin= subprocess.PIPE, stdout= subprocess.PIPE,shell=True)
            awk_sort.wait()
            output = awk_sort.communicate()[0]
            print output.rstrip()

        #!/usr/bin/python
        #author: Bryan Bishop <kanzure@gmail.com>
        #date: 2010-03-03
        #purpose: given a link on the command line to sciencedirect.com, download the associated PDF and put it in "sciencedirect.pdf" or something
        import os
        import re
        import pycurl
        #from BeautifulSoup import BeautifulSoup
        from lxml import etree
        import lxml.html
        from StringIO import StringIO
        from string import join, split

        user_agent = "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.5) Gecko/20091123 Iceweasel/3.5.5 (like Firefox/3.5.5; Debian-3.5.5-1)"

        # def interscience(url):
        '''downloads the PDF from sciencedirect given a link to an article'''
        url = str(url)
        buffer = StringIO()

        curl = pycurl.Curl()
        curl.setopt(curl.URL, url)
        curl.setopt(curl.WRITEFUNCTION, buffer.write)
        curl.setopt(curl.VERBOSE, 0)
        curl.setopt(curl.USERAGENT, user_agent)
        curl.setopt(curl.TIMEOUT, 20)
        curl.perform()
        curl.close()

        buffer = buffer.getvalue().strip()
        html = lxml.html.parse(StringIO(buffer))

        pdf_href = []
        for item in html.getroot().iter('a'):
            if (('id' in item.attrib) and  ('href' in item.attrib) and item.attrib['id']=='pdfLink'):
                pdf_href.append(item.attrib['href'])


        pdf_href = pdf_href[0]
        #now let's get the article title

        title_div = html.find("head/title")
        paper_title = title_div.text
        paper_title = paper_title.replace("\n", "")
        if paper_title[-1] == " ": paper_title = paper_title[:-1]
        re.sub('[^a-zA-Z0-9_\-.() ]+', '', paper_title)
        paper_title = paper_title.strip()
        paper_title = re.sub(' ','_',paper_title)

        #now fetch the document for the user
        command = "wget --user-agent=\"pyscholar/blah\" --output-document=\"%s.pdf\" \"%s\"" % (paper_title, pdf_href)
        os.system(command)
        print "\n\n"
            # interscience("http://www.sciencedirect.com/science/article/pii/S0163638307000628")
        # os.remove(cookies)
        return html


    def twill_download(self, url, cookies,proxy=''):
        # self.url="%(ezproxy_host)s"%form_data
        # self.database_link="%(database_link)s"%form_data
        # self.username="%(user)s"%form_data
        # self.password="%(pass)s"%form_data
        # self.user_tag="%(user_tag)s"%form_data
        # self.pass_tag="%(pass_tag)s"%form_data
        # self.Form_id="%(Form_id)s"%form_data
        # self.submit_tag_name="%(submit_tag_name)s"%form_data
        # self.submit_tag_value="%(submit_tag_value)s"%form_data
        # self.Form_Type="%(Form_Type)s"%form_data
        # self.log_done="%(Log_test)s"%form_data
        link = url;
        # lg = url['log_out'];
        # url_logout = lg['log_out'];
        # ez_link = lg['ez_link']
        # twil__headers = lg['headers']

        if proxy!='':
            import subprocess
            #phantomjs --webdriver=8080 --webdriver-selenium-grid-hub=http://127.0.0.1:4444
            #phantomjs --webdriver=8080 --webdriver-selenium-grid-hub=http://127.2.25.129:4444
            #st='phantomjs --webdriver=8080 --webdriver-selenium-grid-hub=http://'+ip+':4444'
            # st='export http_proxy="http://'+proxy+'"'
            st='export HTTP_PROXY='+proxy
            awk_sort = subprocess.Popen( [st ], stdin= subprocess.PIPE, stdout= subprocess.PIPE,shell=True)
            awk_sort.wait()
            output = awk_sort.communicate()[0]
            print output.rstrip()

        try:
            link = lg['pdf_link']
            # site = urlparse2(link.absolute_url).hostname
        except:
            pass
            # site = urlparse2(link).hostname





        # self.a.config("readonly_controls_writeable", 1)
        # self.b = self.a.get_browser()
        # self.b.set_agent_string("Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.14) Gecko/20080404 Firefox/2.0.0.14")
        # self.b.clear_cookies()
        twill = import_mod(from_module='twill')

        # t_com = twill.commands
        # t_com.reset_browser
        # t_com.reset_output
        t_com = twill.commands

        ## get the default browser
        t_brw = t_com.get_browser()
        try:
            t_brw.set_agent_string(
                "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.14) Gecko/20080404 Firefox/2.0.0.14")

            t_com.add_extra_header('User-agent',
                                   'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')
            t_com.add_extra_header('Accept',
                                   'text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5;application/json;text/javascript;*/*')
            t_com.add_extra_header('Accept-Language', 'en,hu;q=0.8,en-us;q=0.5,hu-hu;q=0.3')
            t_com.add_extra_header('Accept-Encoding', 'gzip, deflate')
            t_com.add_extra_header('Accept-Charset', 'ISO-8859-1,utf-8;q=0.7,*;q=0.7')
            t_com.add_extra_header('Keep-Alive', '300')
            t_com.add_extra_header('Connection', 'keep-alive')
            t_com.add_extra_header('Cache-Control', 'max-age=0')
            # t_com.add_extra_header('Referer', ez_link)
            t_com.add_extra_header('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8')
            t_com.add_extra_header('X-Requested-With', 'XMLHttpRequest')
        except:
            t_com.add_extra_header('User-agent',
                                   'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')
            t_com.add_extra_header('Accept',
                                   "text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5;application/json;text/javascript;*/*")
            t_com.add_extra_header('Accept-Language', 'en,hu;q=0.8,en-us;q=0.5,hu-hu;q=0.3')
            t_com.add_extra_header('Accept-Encoding', 'gzip, deflate')
            t_com.add_extra_header('Accept-Charset', 'ISO-8859-1,utf-8;q=0.7,*;q=0.7')
            t_com.add_extra_header('Keep-Alive', '300')
            t_com.add_extra_header('Connection', 'keep-alive')
            t_com.add_extra_header('Cache-Control', 'max-age=0')
            # t_com.add_extra_header('Referer', ez_link)
            t_com.add_extra_header('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8')
            t_com.add_extra_header('X-Requested-With', 'XMLHttpRequest')


            # t_brw.set_agent_string(twil__headers)

        # cookies=cookies.replace('/','\\')
        try:
            t_brw.load_cookies(cookies)
        except:pass
        # socket=import_mod(from_module='socket')
        # socket.setdefaulttimeout(300)
        ## open the url
        # url = 'http://google.com'
        # t_brw.find_link(link)
        # t_brw.go(link)
        print '@@@@@@@@@@@@@ link download by twill is @@@@@@@@@@@@'
        print link
        print '@@@@@@@@@@@@@ link download by twill is @@@@@@@@@@@@'
        try:
            s = link.absolute_url
            t_brw.follow_link(link)
        except:
            t_brw.go(link)
            # class link_n(object):
            #     def __init__(self):
            #         self.absolute_url = link
            #         self.base_url = ez_link
            #         self.url=ez_link
            #     def url(self):
            #         return self
            # link=link_n.url
        # t_brw.follow_link(link)
        html0 = t_brw.result.page

        print '@@@@@@@@@@@@@ html0 download by twill is @@@@@@@@@@@@'
        print html0[:20]
        print '@@@@@@@@@@@@@ html0 download by twill is @@@@@@@@@@@@'
        # time.sleep(10)




        link2 = t_brw.result.url
        link2 = link.absolute_url
        if not (html0[:4] == '%PDF') or html0 == []:
            t_brw.go(link2)
            html, cookies = MECAHNIZM('', '', cookies=cookies, url=link2).speed_download(link2)
            # html3,pr,upss,cookies=web().download_mechanism_link(link,'',cookies=cookies)
            if not (html[:4] == '%PDF') or html == []:
                t_brw.save_cookies(cookies)
                t_brw = t_com.get_browser()
                t_brw.set_agent_string(
                    "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.14) Gecko/20080404 Firefox/2.0.0.14")
                t_brw.load_cookies(cookies)
                # socket=import_mod(from_module='socket')
                # socket.setdefaulttimeout(300)
                html3, pr, upss, cookies = web().download_mechanism_link(link, '', cookies=cookies)
                t_brw.go(link2)
                html = t_brw.result.page

                print '@@@@@@@@@@@@@ html download by twill is @@@@@@@@@@@@'
                print html
                print '@@@@@@@@@@@@@ html download by twill is @@@@@@@@@@@@'
                # time.sleep(10)
        else:
            html = html0
        # t_brw.go(url_logout)
        os.remove(cookies)
        return html
# ${OPENSHIFT_HOMEDIR}/app-root/runtime/srv/python/bin/python ${OPENSHIFT_HOMEDIR}/app-root/runtime/srv/tornado5/configs/Links_site/www_sciencedirect_com.py
if __name__ == '__main__':
    #HOW TO USE:
    url = "http://127.0.0.1/1752-153X-2-5%20-%20Copy.pdf"
    url = "http://127.0.0.1/1752-153X-2-5.pdf"
    url = 'http://ieeexplore.ieee.org/xpl/articleDetails.jsp?tp=&arnumber=6180383&queryText%3Dpower' #91 KB
    # url = "http://127.0.0.1/"
    # url = "http://dl.acm.org/citation.cfm?id=99977.100000&coll=DL&dl=ACM"
    url='http://www.sciencedirect.com/science/article/pii/S0165176511002710'
    url='http://www.sciencedirect.com/science/article/pii/S2214629616300354'
    # url="http://www.sciencedirect.com.lib.just.edu.jo/science/article/pii/S009630031630282X/pdfft?md5=a22b846cbebf75dd7e816d7586a1a797&pid=1-s2.0-S009630031630282X-main.pdf"
    link=LINK(url).get_pdf_link()
    # link=LINK(url).curl_download(url)

    from optparse import OptionParser

    parser = OptionParser(description=__doc__)
    parser.add_option('-a', dest='url', help='adress url file name to be downloaded like:www.google.com')
    parser.add_option('-p', dest='url', help=' proxy setting for url file name to be download like:121.121.21.21:90')
    parser.add_option('-u', dest='user_name', help='user & password of proxy setting')
    parser.add_option('-i', dest='input_fname', help='file name to be watermarked (pdf)')
    parser.add_option('-w', dest='watermark_fname', help='watermark file name (pdf)')
    parser.add_option('-d', dest='pdfdir', help='make pdf files in this directory')
    parser.add_option('-o', dest='outdir', help='outputdir used with option -d', default='tmp')
    options, args = parser.parse_args()
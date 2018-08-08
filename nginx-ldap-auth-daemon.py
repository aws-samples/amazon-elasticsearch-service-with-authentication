#!/bin/sh
''''which python2 >/dev/null && exec python2 -u "$0" "$@" &>>$LOG # '''
''''which python  >/dev/null && exec python  -u "$0" "$@" &>>$LOG # '''

# Copyright (C) 2014-2015 Nginx, Inc.
# This code has been modified. Portions copyright 2017 Amazon.com, Inc. or its affiliates. Please see LICENSE.txt for applicable license terms and NOTICE.txt for applicable notices.
# Modifications - Added code for LDAP and AWS IAM Authorization by matching AD groups to IAM roles and checking for IAM Policies.

import sys, os, signal, base64, ldap, Cookie, argparse, boto3
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

#Listen = ('localhost', 8888)
#Listen = "/tmp/auth.sock"    # Also uncomment lines in 'Requests are
                              # processed with UNIX sockets' section below

# -----------------------------------------------------------------------------
# Different request processing models: select one
# -----------------------------------------------------------------------------
# Requests are processed in separate thread
import threading
from SocketServer import ThreadingMixIn
class AuthHTTPServer(ThreadingMixIn, HTTPServer):
    pass
# -----------------------------------------------------------------------------
# Requests are processed in separate process
#from SocketServer import ForkingMixIn
#class AuthHTTPServer(ForkingMixIn, HTTPServer):
#    pass
# -----------------------------------------------------------------------------
# Requests are processed with UNIX sockets
#import threading
#from SocketServer import ThreadingUnixStreamServer
#class AuthHTTPServer(ThreadingUnixStreamServer, HTTPServer):
#    pass
# -----------------------------------------------------------------------------

class AuthHandler(BaseHTTPRequestHandler):

    # Return True if request is processed and response sent, otherwise False
    # Set ctx['user'] and ctx['pass'] for authentication
    def do_GET(self):

        ctx = self.ctx

        ctx['action'] = 'input parameters check'
        for k, v in self.get_params().items():
            ctx[k] = self.headers.get(v[0], v[1])
            if ctx[k] == None:
                self.auth_failed(ctx, 'required "%s" header was not passed' % k)
                return True

        ctx['action'] = 'performing authorization'
        auth_header = self.headers.get('Authorization')
        auth_cookie = self.get_cookie(ctx['cookiename'])

        if auth_cookie != None and auth_cookie != '':
            auth_header = "Basic " + auth_cookie
            self.log_message("using username/password from cookie %s" %
                             ctx['cookiename'])
        else:
            self.log_message("using username/password from authorization header")

        if auth_header is None or not auth_header.lower().startswith('basic '):

            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="' + ctx['realm'] + '"')
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()

            return True

        ctx['action'] = 'decoding credentials'

        try:
            auth_decoded = base64.b64decode(auth_header[6:])
            user, passwd = auth_decoded.split(':', 1)

        except:
            self.auth_failed(ctx)
            return True

        ctx['user'] = user
        ctx['pass'] = passwd

        # Continue request processing
        return False

    def get_cookie(self, name):
        cookies = self.headers.get('Cookie')
        if cookies:
            authcookie = Cookie.BaseCookie(cookies).get(name)
            if authcookie:
                return authcookie.value
            else:
                return None
        else:
            return None


    # Log the error and complete the request with appropriate status
    def auth_failed(self, ctx, errmsg = None, httpCode = 401):

        msg = 'Error while ' + ctx['action']
        if errmsg:
            msg += ': ' + errmsg

        ex, value, trace = sys.exc_info()

        if ex != None:
            msg += ": " + str(value)

        if ctx.get('url'):
            msg += ', server="%s"' % ctx['url']

        if ctx.get('user'):
            msg += ', login="%s"' % ctx['user']

        self.log_error(msg)
        self.send_response(httpCode)
        if httpCode == 401:
            self.send_header('WWW-Authenticate', 'Basic realm="' + ctx['realm'] + '"')
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()

    def get_params(self):
        return {}

    def log_message(self, format, *args):
        if len(self.client_address) > 0:
            addr = BaseHTTPRequestHandler.address_string(self)
        else:
            addr = "-"

        if not hasattr(self, 'ctx'):
            user = '-'
        else:
            user = self.ctx['user']

        sys.stdout.write("%s - %s [%s] %s\n" % (addr, user,
                         self.log_date_time_string(), format % args))
        sys.stdout.flush()

    def log_error(self, format, *args):
        self.log_message(format, *args)


# Verify username/password against LDAP server
class LDAPAuthHandler(AuthHandler):
    # Parameters to put into self.ctx from the HTTP header of auth request
    params =  {
             # parameter      header         default
             'realm': ('X-Ldap-Realm', 'Restricted'),
             'url': ('X-Ldap-URL', None),
             'basedn': ('X-Ldap-BaseDN', None),
             'template': ('X-Ldap-Template', '(cn=%(username)s)'),
             'binddn': ('X-Ldap-BindDN', ''),
             'bindpasswd': ('X-Ldap-BindPass', ''),
             'cookiename': ('X-CookieName', ''),
	         'origuri': ('X-Original-URI', ''),
             'origmethod': ('X-Original-Mehod', ''),
	         'targetarn': ('X-Target-ARN', ''),
             'groupprefix': ('X-GroupPrefix','')
        }

    @classmethod
    def set_params(cls, params):
        cls.params = params

    def get_params(self):
        return self.params

    # GET handler for the authentication request
    def do_GET(self):

        ctx = dict()
        self.ctx = ctx

        ctx['action'] = 'initializing basic auth handler'
        ctx['user'] = '-'

        if AuthHandler.do_GET(self):
            # request already processed
            return

        ctx['action'] = 'empty password check'
        if not ctx['pass']:
            self.auth_failed(ctx, 'attempt to use empty password')
            return

        try:
            # check that uri and baseDn are set
            # either from cli or a request
            if not ctx['url']:
                self.log_message('LDAP URL is not set!')
                return
            if not ctx['basedn']:
                self.log_message('LDAP baseDN is not set!')
                return

            ctx['action'] = 'initializing LDAP connection'
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW);
            ldap_obj = ldap.initialize(ctx['url']);

            # See http://www.python-ldap.org/faq.shtml
            # uncomment, if required
            # ldap_obj.set_option(ldap.OPT_REFERRALS, 0)

            ctx['action'] = 'binding as search user'
            ldap_obj.bind_s(ctx['binddn'], ctx['bindpasswd'], ldap.AUTH_SIMPLE)

            ctx['action'] = 'preparing search filter'
            searchfilter = ctx['template'] % { 'username': ctx['user'] }

            self.log_message(('searching on server "%s" with base dn ' + \
                              '"%s" with filter "%s"') %
                              (ctx['url'], ctx['basedn'], searchfilter))

            ctx['action'] = 'running search query'
            results = ldap_obj.search_s(ctx['basedn'], ldap.SCOPE_SUBTREE,
                                          searchfilter, ['objectclass'], 1)

            ctx['action'] = 'verifying search query results'
            if len(results) < 1:
                self.auth_failed(ctx, 'no objects found')
                return

            ctx['action'] = 'binding as an existing user'
            ldap_dn = results[0][0]
            ctx['action'] += ' "%s"' % ldap_dn
            ldap_obj.bind_s(ldap_dn, ctx['pass'], ldap.AUTH_SIMPLE)

            self.log_message('Auth OK for user "%s"' % (ctx['user']))
            try:
                ctx['action'] = 'checking for IAM authorization using LDAP/AD group membership'
                searchfilter='(|(&(objectClass=Group)(cn=%s*)(member=%s)))' % (ctx['groupprefix'],ldap_dn)
                results = ldap_obj.search_s(ctx['basedn'], ldap.SCOPE_SUBTREE, searchfilter, ['name'])
                self.log_message('enumerating through AD/LDAP groups: %s' % (results))
                client = boto3.client('iam')
                methods ={'GET':'es:ESHttpGet','PUT':'es:ESHttpPut','HEAD':'es:ESHttpHead','POST':'es:ESHttpPost','DELETE':'es:ESHttpDelete'}
                for group in results:
                    self.log_message('checking matching IAM Role for AD/LDAP group %s' % (group[1]['name'][0]))
                    try:
                        roleDetails = client.get_role(
                            RoleName = group[1]['name'][0]
                        )
                    except:
                        self.log_message('failed getting IAM Role for AD/LDAP group %s' % (group[1]['name'][0]))
                        continue

                    if roleDetails:
                            self.log_message('evaluating IAM policies for user %s using IAM role %s on resource %s' % (ctx['user'],roleDetails['Role']['Arn'],ctx['origuri']))
                            try:
                                accessDetails = client.simulate_principal_policy(
                                PolicySourceArn=roleDetails['Role']['Arn'],
                                ActionNames=[methods[ctx['origmethod']]],
                                ResourceArns=['%s%s' % (ctx['targetarn'],ctx['origuri'])]
                                )
                            except:
                                self.log_message('failed evaluating IAM policies for user %s using IAM role %s on resource %s' % (ctx['user'],roleDetails['Role']['Arn'],ctx['origuri']))
                                continue

                            if accessDetails:
                                try:
                                    if accessDetails['EvaluationResults'][0]['EvalDecision'] == 'allowed':
                                        # Successfully authenticated user
                                        self.log_message('access allowed for user %s with IAM role %s' % (ctx['user'],roleDetails['Role']['Arn']))
                                        self.send_response(200)
                                        self.end_headers()
                                        break
                                except:
                                    self.log_message('failed retrieving evaluation decision from result: %s' % (accessDetails))
                                    continue
                            else:
                                self.log_message('access deined for user %s with IAM role %s' % (ctx['user'],roleDetails['Role']['Arn']))
            except:
                # Unsuccessful authorization
                self.log_message('access denied for user "%s". No favourable IAM Role/Policy found' % (ctx['user']))
                self.auth_failed(ctx,'No favourable IAM Role/Policy found',403)
                self.send_response(403)

            # Unsuccessful authorization
            self.log_message('access denied for user "%s". No favourable IAM Role/Policy found' % (ctx['user']))
            self.auth_failed(ctx,'No favourable IAM Role/Policy found',403)
            self.send_response(403)

        except:
            self.log_message('Auth failed for user %s' % (ctx['user']))
            self.auth_failed(ctx)

def exit_handler(signal, frame):
    global Listen

    if isinstance(Listen, basestring):
        try:
            os.unlink(Listen)
        except:
            ex, value, trace = sys.exc_info()
            sys.stderr.write('Failed to remove socket "%s": %s\n' %
                             (Listen, str(value)))
    sys.exit(0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="""Simple Nginx LDAP authentication helper.""")
    # Group for listen options:
    group = parser.add_argument_group("Listen options")
    group.add_argument('--host',  metavar="hostname",
        default="localhost", help="host to bind (Default: localhost)")
    group.add_argument('-p', '--port', metavar="port", type=int,
        default=8888, help="port to bind (Default: 8888)")
    # ldap options:
    group = parser.add_argument_group(title="LDAP options")
    group.add_argument('-u', '--url', metavar="URL",
        default="ldap://localhost:389",
        help=("LDAP URI to query (Default: ldap://localhost:389)"))
    group.add_argument('-b', metavar="baseDn", dest="basedn", default='',
        help="LDAP base dn (Default: unset)")
    group.add_argument('-D', metavar="bindDn", dest="binddn", default='',
        help="LDAP bind DN (Default: anonymous)")
    group.add_argument('-w', metavar="passwd", dest="bindpw", default='',
        help="LDAP password for the bind DN (Default: unset)")
    group.add_argument('-f', '--filter', metavar='filter',
        default='(cn=%(username)s)',
        help="LDAP filter (Default: cn=%%(username)s)")
    # http options:
    group = parser.add_argument_group(title="HTTP options")
    group.add_argument('-R', '--realm', metavar='"Restricted Area"',
        default="Resticted", help='HTTP auth realm (Default: "Restricted")')
    group.add_argument('-c', '--cookie', metavar="cookiename",
        default="", help="HTTP cookie name to set in (Default: unset)")
    group.add_argument('-o', '--origuri', metavar="origuri",
        default="", help="Original Request URI (Default: unset)")
    group.add_argument('-m', '--origmethod', metavar="origmethod",
        default="", help="Original Request Method (Default: unset)")
    group.add_argument('-t', '--targetarn', metavar="targetarn",
        default="", help="Target ARN (Default: unset)")
    group.add_argument('-g', '--groupprefix', metavar="groupprefix",
        default="", help='AD/LDAP Group Prefix (Default: unset)')

    args = parser.parse_args()
    global Listen
    Listen = (args.host, args.port)
    auth_params = {
             'realm': ('X-Ldap-Realm', args.realm),
             'url': ('X-Ldap-URL', args.url),
             'basedn': ('X-Ldap-BaseDN', args.basedn),
             'template': ('X-Ldap-Template', args.filter),
             'binddn': ('X-Ldap-BindDN', args.binddn),
             'bindpasswd': ('X-Ldap-BindPass', args.bindpw),
             'cookiename': ('X-CookieName', args.cookie),
	         'origuri': ('X-Original-URI', args.origuri),
             'origmethod': ('X-Original-Method', args.origmethod),
             'targetarn': ('X-Target-ARN', args.targetarn),
             'groupprefix': ('X-GroupPrefix', args.groupprefix)
    }
    LDAPAuthHandler.set_params(auth_params)
    server = AuthHTTPServer(Listen, LDAPAuthHandler)
    signal.signal(signal.SIGINT, exit_handler)
    server.serve_forever()

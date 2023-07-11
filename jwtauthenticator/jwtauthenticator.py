from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator
from jupyterhub.auth import LocalAuthenticator
from jupyterhub.utils import url_path_join
import jwt
from tornado import (
    gen,
    web,
)
from traitlets import (
    Bool,
    List,
    Unicode,
)
from urllib import parse


class JSONWebTokenLoginHandler(BaseHandler):

    async def get(self):
        header_name = self.authenticator.header_name
        cookie_name = self.authenticator.cookie_name
        param_name = self.authenticator.param_name

        auth_header_content = self.request.headers.get(header_name, "") if header_name else None
        auth_cookie_content = self.get_cookie(cookie_name, "") if cookie_name else None
        auth_param_content = self.get_argument(param_name, default="") if param_name else None
        self.authenticator.log_text('param_name:"' + str(param_name) + '"')
        self.authenticator.log_text('auth_param_content:' + str(auth_param_content))

        signing_certificate = self.authenticator.signing_certificate
        secret = self.authenticator.secret
        algorithms = self.authenticator.algorithms

        username_claim_field = self.authenticator.username_claim_field
        extract_username = self.authenticator.extract_username
        audience = self.authenticator.expected_audience

        auth_url = self.authenticator.auth_url
        retpath_param = self.authenticator.retpath_param

        _url = url_path_join(self.hub.server.base_url, 'home')
        next_url = self.get_argument('next', default=False)
        if next_url:
            _url = next_url
            if param_name:
                auth_param_content = parse.parse_qs(parse.urlparse(next_url).query).get(param_name, "")
                if isinstance(auth_param_content, list):
                    auth_param_content = auth_param_content[0]
                self.authenticator.log_text('auth_param_content:' + str(auth_param_content))

        if auth_url and retpath_param:
            auth_url += ("{prefix}{param}=https://{host}{url}".format(
                prefix='&' if '?' in auth_url else '?',
                param=retpath_param,
                host=self.request.host,
                url=_url,
            ))

        if bool(auth_header_content) + bool(auth_cookie_content) + bool(auth_param_content) > 1:
            self.authenticator.log_text('auth_failed, multiple tokens')
            raise web.HTTPError(400)
        elif auth_header_content:
            token = auth_header_content
        elif auth_cookie_content:
            token = auth_cookie_content
        elif auth_param_content:
            token = auth_param_content
            self.authenticator.log_text('token:' + str(token))
        else:
            self.authenticator.log_text('auth_failed, no token')
            return self.auth_failed(auth_url)

        try:
            if secret:
                claims = self.verify_jwt_using_secret(token, secret, algorithms, audience)
                self.authenticator.log_text('claims from secret:' + str(claims))
            elif signing_certificate:
                claims = self.verify_jwt_with_claims(token, signing_certificate, algorithms, audience)
                self.authenticator.log_text('claims from signing_certificate:' + str(claims))
            else:
                self.authenticator.log_text('auth_failed, no way to verify token')
                return self.auth_failed(auth_url)
        except jwt.exceptions.InvalidTokenError:
            return self.auth_failed(auth_url)

        username = self.retrieve_username(claims, username_claim_field, extract_username=extract_username)
        self.authenticator.log_text('username: ' + str(username))
        user = await self.auth_to_user({'name': username})
        self.set_login_cookie(user)

        self.redirect(_url)

    def auth_failed(self, redirect_url):
        if redirect_url:
            self.redirect(redirect_url)
        else:
            raise web.HTTPError(401)

    def verify_jwt_with_claims(self, token, signing_certificate, algorithms, audience):
        self.authenticator.log_text('verify_jwt_with_claims: algorithms=' + str(algorithms))
        opts = {}
        if not audience:
            opts = {"verify_aud": False}
        with open(signing_certificate, 'r') as rsa_public_key_file:
            self.authenticator.log_text('found signing_certificate')
            try:
                dec = jwt.decode(token, rsa_public_key_file.read(), algorithms=algorithms, audience=audience,
                                 options=opts)
                self.authenticator.log_text('jwt = ' + str(dec))
                return dec
            except Exception as e:
                self.authenticator.log_create()
                raise e

    @staticmethod
    def verify_jwt_using_secret(json_web_token, secret, algorithms, audience):
        opts = {}
        if not audience:
            opts = {"verify_aud": False}
        return jwt.decode(json_web_token, secret, algorithms=algorithms, audience=audience, options=opts)

    @staticmethod
    def retrieve_username(claims, username_claim_field, extract_username):
        username = claims[username_claim_field]
        if extract_username:
            if "@" in username:
                return username.split("@")[0]
        return username


class JSONWebTokenAuthenticator(Authenticator):
    @staticmethod
    def print_exception():
        import sys
        import traceback
        exc_type, exc_value, exc_tb = sys.exc_info()
        except_string = traceback.format_exception(exc_type, exc_value, exc_tb)
        print(except_string)
        return except_string
    
    def log_create(self):
        if not self.debug:
            return
        logr = open('app.log', 'a')
        exceptions = print_exception()
        logr.write(f"Failed to load: {str(exceptions)}\n")
    
    def log_text(self, text):
        if not self.debug:
            return
        logr = open('app.log', 'a')
        logr.write(f"Log: {str(text)}\n")
        print(f"Log: {str(text)}\n")
    
    """
    Accept the authenticated JSON Web Token from header.
    """
    auth_url = Unicode(
        config=True,
        help="""URL for redirecting to in the case of invalid auth token""")

    retpath_param = Unicode(
        config=True,
        help="""Name of query param for auth_url to pass return URL""")

    header_name = Unicode(
        config=True,
        help="""HTTP header to inspect for the authenticated JSON Web Token.""")

    cookie_name = Unicode(
        config=True,
        help="""The name of the cookie field used to specify the JWT token""")

    param_name = Unicode(
        config=True,
        help="""The name of the query parameter used to specify the JWT token""")

    signing_certificate = Unicode(
        config=True,
        help="""
        The public certificate of the private key used to sign the incoming JSON Web Tokens.

        Should be a path to an X509 PEM format certificate filesystem.
        """
    )

    secret = Unicode(
        config=True,
        help="""Shared secret key for siging JWT token. If defined, it overrides any setting for signing_certificate""")

    algorithms = List(
        default_value=['HS256'],
        config=True,
        help="""Specify which algorithms you would like to permit when validating the JWT""")

    username_claim_field = Unicode(
        default_value='username',
        config=True,
        help="""
        The field in the claims that contains the user name. It can be either a straight username,
        of an email/userPrincipalName.
        """
    )

    extract_username = Bool(
        default_value=True,
        config=True,
        help="""
        Set to true to split username_claim_field and take the part before the first `@`
        """
    )

    expected_audience = Unicode(
        default_value='',
        config=True,
        help="""HTTP header to inspect for the authenticated JSON Web Token."""
    )

    debug = Bool(
        default_value=False,
        config=True,
        help="""Create a debug log on the server for troubleshooting"""
    )

    def get_handlers(self, app):
        return [
            (r'/login', JSONWebTokenLoginHandler),
        ]

    @gen.coroutine
    def authenticate(self, *args):
        raise NotImplementedError()

    async def refresh_user(self, user, handler=None):
        self.log_text("REFRESH_USER called")
        # auth_state = await user.get_auth_state()
        # self.log_text(str(user))
        # self.log_text(str(auth_state))
        return True


class JSONWebTokenLocalAuthenticator(JSONWebTokenAuthenticator, LocalAuthenticator):
    """
    A version of JSONWebTokenAuthenticator that mixes in local system user creation
    """
    pass

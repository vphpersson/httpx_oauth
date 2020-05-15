from dataclasses import dataclass
from hashlib import sha1
from typing import Generator, ClassVar, Optional
from secrets import token_bytes
from time import time
from urllib.parse import quote
from base64 import b64encode
from hmac import new as hmac_new
from itertools import chain

from httpx import Auth
from httpx._models import Request, Response, URL, QueryParams


@dataclass
class RequestTokenResponse:
    oauth_token: str
    oauth_token_secret: str
    oauth_callback_confirmed: bool


@dataclass
class OAuthAuth(Auth):
    requires_request_body: ClassVar[bool] = True

    consumer_key: str
    consumer_secret: str
    oauth_access_token: Optional[str] = None
    oauth_access_token_secret: Optional[str] = None

    @property
    def oauth_base_parameters(self):
        oauth_base_parameters = dict(
            oauth_consumer_key=self.consumer_key,
            oauth_nonce=sha1(token_bytes(nbytes=32)).hexdigest(),
            oauth_signature_method='HMAC-SHA1',
            oauth_timestamp=str(int(time())),
            oauth_version='1.0'
        )

        if self.oauth_access_token:
            oauth_base_parameters['oauth_token'] = self.oauth_access_token

        return oauth_base_parameters

    def auth_flow(self, request: Request) -> Generator[Request, Response, None]:
        """
        Update the request.

        :param request: A request to be updated with OAuth parameters.
        """

        oauth_parameters = self.oauth_base_parameters

        hmac_message_query_string = str(
            QueryParams(
                sorted(
                    chain(
                        QueryParams(request.url.query).items(),
                        (
                            QueryParams(request.content.decode()).items()
                            if request.method == 'POST' and request.headers.get('content-type') == 'application/x-www-form-urlencoded'
                            else []
                        ),
                        oauth_parameters.items(),
                    )
                )
            )
        )

        oauth_parameters['oauth_signature'] = b64encode(
            s=hmac_new(
                key='&'.join([
                    quote(string=self.consumer_secret, safe=b"~"),
                    quote(string=self.oauth_access_token_secret or '', safe=b"~")
                ]).encode(),
                msg='&'.join(
                    quote(string=element, safe=b'~')
                    for element in (
                        request.method.upper(),
                        f'{request.url.scheme}://{request.url.host}{request.url.path}',
                        hmac_message_query_string
                    )
                ).encode(),
                digestmod=sha1
            ).digest()
        ).decode()

        # The OAuth parameters are added to the query.
        request.url = URL(url=request.url, params=oauth_parameters)

        # request.headers['Authorization'] = 'OAuth ' + ', '.join([
        #     f'{key}="{value}"' for key, value in oauth_parameters.items()]
        # )

        yield request

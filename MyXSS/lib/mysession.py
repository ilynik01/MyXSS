from requests import Session
from requests.exceptions import TooManyRedirects



class MySession(Session):
    def __init__(self, max_redirects=3, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_redirects = max_redirects

    def resolve_redirects(self, resp, req, stream=False, timeout=None,
                          verify=True, cert=None, proxies=None, **adapter_kwargs):
        i = 0
        for response in super().resolve_redirects(resp, req, stream, timeout,
                                                  verify, cert, proxies, **adapter_kwargs):
            if i >= self.max_redirects:
                raise TooManyRedirects('Exceeded maximum number of redirects.')
            yield response
            i += 1

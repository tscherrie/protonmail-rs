#!/usr/bin/env python3
"""Minimal stdio to Streamable HTTP adapter for a single trusted MCP server.

Credentials are read from a private file; never place them in process arguments.
No external Python dependencies. Serial dispatch matches the server's mailbox
lock. This server has no client-side sampling or elicitation callbacks.
"""
import argparse
import json
import sys
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class RemoteClient:
    def __init__(self, url, token, opener=None, emit=None):
        self.url = url
        self.token = token
        self.opener = opener or urllib.request.build_opener(NoRedirect())
        self.emit = emit or (lambda message: None)
        self.session = None
        self.version = None
        self.initialize_request = None

    def post(self, request, emit=True):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream', 'Authorization': 'Bearer ' + self.token}
        if self.session:
            headers['Mcp-Session-Id'] = self.session
        if self.version:
            headers['MCP-Protocol-Version'] = self.version
        req = urllib.request.Request(self.url, data=json.dumps(request).encode(), headers=headers, method='POST')
        with self.opener.open(req, timeout=180) as response:
            self.session = response.headers.get('Mcp-Session-Id', self.session)
            if response.status == 202 or 'id' not in request:
                return None
            if 'text/event-stream' not in response.headers.get('Content-Type', ''):
                return json.load(response)
            data = []
            for raw in response:
                event_line = raw.decode('utf-8').rstrip('\r\n')
                if event_line.startswith('data:'):
                    data.append(event_line[5:].lstrip(' '))
                elif not event_line and data and ''.join(data).strip():
                    message = json.loads('\n'.join(data))
                    data = []
                    if message.get('id') == request['id']:
                        return message
                    if emit:
                        self.emit(message)
        raise RuntimeError('MCP response stream ended without a matching response')

    def request(self, request):
        try:
            result = self.post(request)
        except urllib.error.HTTPError as error:
            # MCP 404 with a session ID means the request was rejected before
            # tool dispatch. Only this response is safe to replay; never retry
            # timeouts, authorization failures, or arbitrary server errors.
            if error.code != 404 or not self.session or not self.initialize_request:
                raise
            previous_version = self.version
            self.session = None
            self.version = None
            initialized = self.post(self.initialize_request, emit=False)
            self.version = initialized.get('result', {}).get('protocolVersion')
            if not self.version or self.version != previous_version:
                raise RuntimeError('MCP reinitialization changed the negotiated protocol')
            self.post({'jsonrpc': '2.0', 'method': 'notifications/initialized'}, emit=False)
            if request.get('method') == 'notifications/initialized':
                return None
            result = self.post(request)
        if request.get('method') == 'initialize' and result and 'result' in result:
            self.initialize_request = request
            self.version = result['result'].get('protocolVersion')
        return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--token-file', required=True)
    args = parser.parse_args()
    if not args.url.startswith('https://'):
        parser.error('HTTPS is required')
    with open(args.token_file, encoding='utf-8') as f:
        token = f.read().strip()
    emit = lambda message: print(json.dumps(message), flush=True)
    client = RemoteClient(args.url, token, emit=emit)
    for line in sys.stdin:
        if not line.strip():
            continue
        request = json.loads(line)
        try:
            result = client.request(request)
            if result is not None:
                emit(result)
        except Exception as error:
            if 'id' in request:
                # Do not include upstream bodies, headers, or credentials in errors.
                code = getattr(error, 'code', None)
                message = f'Remote MCP request failed ({type(error).__name__}' + (f', HTTP {code}' if code else '') + ').'
                print(json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'error': {'code': -32603, 'message': message}}), flush=True)


if __name__ == '__main__':
    main()

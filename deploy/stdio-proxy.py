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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--token-file', required=True)
    args = parser.parse_args()
    if not args.url.startswith('https://'):
        parser.error('HTTPS is required')
    with open(args.token_file, encoding='utf-8') as f:
        token = f.read().strip()
    session = None
    version = None
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(NoRedirect())
    for line in sys.stdin:
        if not line.strip():
            continue
        request = json.loads(line)
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream', 'Authorization': 'Bearer ' + token}
        if session:
            headers['Mcp-Session-Id'] = session
        if version:
            headers['MCP-Protocol-Version'] = version
        try:
            req = urllib.request.Request(args.url, data=json.dumps(request).encode(), headers=headers, method='POST')
            with opener.open(req, timeout=180) as response:
                session = response.headers.get('Mcp-Session-Id', session)
                if response.status == 202 or 'id' not in request:
                    continue
                if 'text/event-stream' in response.headers.get('Content-Type', ''):
                    data = []
                    result = None
                    for raw in response:
                        event_line = raw.decode('utf-8').rstrip('\r\n')
                        if event_line.startswith('data:'):
                            data.append(event_line[5:].lstrip(' '))
                        elif not event_line and data and ''.join(data).strip():
                            message = json.loads('\n'.join(data))
                            data = []
                            if message.get('id') == request['id']:
                                result = message
                                break
                            print(json.dumps(message), flush=True)
                    if result is None:
                        raise RuntimeError('MCP response stream ended without a matching response')
                else:
                    result = json.load(response)
                if request.get('method') == 'initialize':
                    version = result.get('result', {}).get('protocolVersion')
                print(json.dumps(result), flush=True)
        except Exception as error:
            if 'id' in request:
                # Do not include upstream bodies, headers, or credentials in errors.
                code = getattr(error, 'code', None)
                message = f'Remote MCP request failed ({type(error).__name__}' + (f', HTTP {code}' if code else '') + ').'
                print(json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'error': {'code': -32603, 'message': message}}), flush=True)


if __name__ == '__main__':
    main()

import importlib.util
import io
import json
import pathlib
import unittest
import urllib.error


spec = importlib.util.spec_from_file_location('stdio_proxy', pathlib.Path(__file__).with_name('stdio-proxy.py'))
proxy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy)

INITIALIZE = {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-11-25', 'capabilities': {}, 'clientInfo': {'name': 'test', 'version': '1'}}}
INITIALIZED = {'jsonrpc': '2.0', 'method': 'notifications/initialized'}


class Response(io.BytesIO):
    def __init__(self, body, session=None, status=200, sse=False):
        data = ('data: ' + json.dumps(body) + '\n\n') if sse else json.dumps(body)
        super().__init__(data.encode())
        self.headers = {'Content-Type': 'text/event-stream' if sse else 'application/json'}
        if session:
            self.headers['Mcp-Session-Id'] = session
        self.status = status


class Server:
    def __init__(self):
        self.calls = []
        self.live_session = None
        self.generation = 0
        self.failure = None
        self.version = '2025-11-25'
        self.accepted_tools = 0

    def open(self, req, timeout):
        message = json.loads(req.data)
        session = req.get_header('Mcp-session-id')
        self.calls.append((message['method'], session))
        if self.failure:
            raise self.failure
        if session and session != self.live_session:
            raise urllib.error.HTTPError(req.full_url, 404, 'Session expired', {}, None)
        if message['method'] == 'initialize':
            self.generation += 1
            self.live_session = str(self.generation)
            return Response({'jsonrpc': '2.0', 'id': message['id'], 'result': {'protocolVersion': self.version}}, self.live_session)
        if message['method'].startswith('notifications/'):
            return Response({}, status=202)
        if message['method'] == 'tools/call':
            self.accepted_tools += 1
        return Response({'jsonrpc': '2.0', 'id': message['id'], 'result': {'ok': True}}, sse=True)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.server = Server()
        self.client = proxy.RemoteClient('https://server.invalid/mcp', 'private-test-token', opener=self.server)
        self.client.request(INITIALIZE)
        self.client.request(INITIALIZED)

    def test_expired_session_reinitializes_and_replays_once(self):
        self.server.live_session = None
        result = self.client.request({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': 'send_message'}})
        self.assertEqual(result['id'], 2)
        self.assertTrue(result['result']['ok'])
        self.assertEqual(self.server.accepted_tools, 1)
        self.assertEqual(self.server.calls[2:], [('tools/call', '1'), ('initialize', None), ('notifications/initialized', '2'), ('tools/call', '2')])

    def test_unauthorized_does_not_retry(self):
        self.server.failure = urllib.error.HTTPError(self.client.url, 401, 'Unauthorized', {}, None)
        with self.assertRaises(urllib.error.HTTPError):
            self.client.request({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call'})
        self.assertEqual(len(self.server.calls), 3)

    def test_timeout_does_not_retry(self):
        self.server.failure = TimeoutError()
        with self.assertRaises(TimeoutError):
            self.client.request({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call'})
        self.assertEqual(len(self.server.calls), 3)

    def test_protocol_change_fails_before_replay(self):
        self.server.live_session = None
        self.server.version = 'different-version'
        with self.assertRaisesRegex(RuntimeError, 'protocol'):
            self.client.request({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call'})
        self.assertEqual(self.server.accepted_tools, 0)

    def test_lost_initialized_notification_is_not_duplicated(self):
        self.server.live_session = None
        self.assertIsNone(self.client.request(INITIALIZED))
        self.assertEqual(self.server.calls[2:], [('notifications/initialized', '1'), ('initialize', None), ('notifications/initialized', '2')])


if __name__ == '__main__':
    unittest.main()

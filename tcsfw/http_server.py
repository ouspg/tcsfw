"""HTTP server"""

import asyncio
import hmac
from io import BytesIO
import json
import logging
import os
import pathlib
import tempfile
import traceback
from typing import Dict, Optional, Tuple, List
import zipfile

from aiohttp import web, WSMsgType

from tcsfw.client_api import ClientAPI, APIRequest, APIListener
from tcsfw.model import IoTSystem


class Session(APIListener):
    """A session per web socket"""
    def __init__(self, server: 'HTTPServerRunner', socket: web.WebSocketResponse, request: APIRequest):
        self.server = server
        self.socket = socket
        self.original_request = request
        self.subscribed = False  # subscribed?
        self.server.api.api_listener.append((self, self.original_request))

    def note_system_reset(self, _data: Dict, _system: IoTSystem):
        if self.subscribed:
            self.server.dump_model(self)

    def note_event(self, data: Dict):
        if self.subscribed:
            self.server.send_queue.put_nowait((self, data))

    def close(self):
        """Close the session"""
        self.subscribed = False
        self.server.api.api_listener.remove((self, self.original_request))


class HTTPServerRunner:
    """Run HTTP server locally"""
    PATH = pathlib.Path("html")

    def __init__(self, api: ClientAPI, base_directory=pathlib.Path("."), port=8180, no_auth_ok=False):
        self.api = api
        self.registry = api.registry
        self.logger = logging.getLogger("server")
        self.sample_path = base_directory / "sample"
        self.host = "127.0.0.1"
        self.port = port
        self.auth_token = os.environ.get("TCSFW_SERVER_API_KEY", "")
        if not self.auth_token and not no_auth_ok:
            raise ValueError("No environment variable TCSFW_SERVER_API_KEY (use --no-auth-ok to skip check)")
        if self.auth_token:
            self.host = None  # allow all hosts, when token is present
        self.component_delay = 0
        self.sessions: List[Session] = []
        self.loop = asyncio.get_event_loop()
        self.send_queue: asyncio.Queue[Tuple[Session, Dict]] = asyncio.Queue()
        self.send_queue_target_size = 10

    def run(self):
        """Start sync loop and run the server"""
        self.loop.run_until_complete(self.start_server())
        self.loop.create_task(self.send_worker())
        self.loop.run_forever()
        # registry must be indirect
        self.registry.fallthrough = False

    async def start_server(self):
        """Start the Web server"""
        app = web.Application()
        app.add_routes([
            web.get('/api1/ws/{tail:.+}', self.handle_ws),  # must be first
            web.get('/api1/{tail:.+}', self.handle_http),
            web.post('/api1/{tail:.+}', self.handle_http),
            web.get('/connect/{tail:.+}', self.handle_connect),
        ])
        rr = web.AppRunner(app)
        await rr.setup()
        site = web.TCPSite(rr, self.host, self.port)
        self.logger.info("HTTP server running at %s:%s...", self.host or "*", self.port)
        await site.start()

    async def send_worker(self):
        """A worker to send data to websockets"""
        while True:
            session, d = await self.send_queue.get()
            if session.subscribed:
                self.logger.info("send %s", d)
                await session.socket.send_json(d)
            self.send_queue.task_done()
            if self.component_delay > 0:
                # artificial delay for testing
                await asyncio.sleep(self.component_delay)

    def check_permission(self, request):
        """Check permissions"""
        auth_t = request.headers.get("x-authorization", "").strip()
        if not auth_t:
            auth_t = request.cookies.get("authorization", "").strip()
        if not auth_t:
            if self.auth_token:
                raise PermissionError("No authentication token provided")
        else:
            # compare token constant time to avoid timing attacks
            token_1 = auth_t.encode("utf-8")
            token_2 = self.auth_token.encode("utf-8")
            if not hmac.compare_digest(token_1, token_2):
                raise PermissionError("Invalid API key")

    async def handle_http(self, request):
        """Handle normal HTTP GET or POST request"""
        try:
            self.check_permission(request)

            assert request.path_qs.startswith("/api1/")
            req = APIRequest.parse(request.path_qs[6:])
            self.logger.info("API: %s %s", request.method, req)
            if request.method == "GET":
                res = self.api.api_get(req)
            elif request.method == "POST":
                # read all data as easy solution to async problem
                if request.content_type == "application/json" or not request.content_type:
                    # JSON data
                    with tempfile.TemporaryFile() as tmp:
                        data = await self.read_stream_to_file(request, tmp)
                        res = self.api.api_post(req, data)
                elif request.content_type == "application/zip":
                    # ZIP file
                    res = await self.api_post_zip(req, request)
                else:
                    raise ValueError("Unexpected content-type")
            else:
                raise NotImplementedError("Unexpected method/path")
            return web.Response(text=json.dumps(res))
        except NotImplementedError:
            return web.Response(status=400)
        except FileNotFoundError:
            return web.Response(status=404)
        except PermissionError:
            return web.Response(status=401)
        except Exception:  # pylint: disable=broad-except
            traceback.print_exc()
            return web.Response(status=500)

    async def handle_connect(self, request):
        """Handle connect request, intended for launcher, but in testing can be used directly"""
        # simply return pointer to itself
        host = request.headers.get("Host", "localhost")
        res = {"host": host}
        return web.Response(text=json.dumps(res))

    async def read_stream_to_file(self, request, file: BytesIO) -> Optional[BytesIO]:
        """Read stream to a file, return data or None if no data"""
        r_size = 0
        b = await request.content.read(1024)
        while b:
            r_size += len(b)
            file.write(b)
            b = await request.content.read(1024)
        file.seek(0)
        return file if r_size > 0 else None

    async def api_post_zip(self, api_request: APIRequest, request):
        """Handle POST request with zip file"""
        # unzip stream to temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # create temporary file, extract to directory, delete the temporary file
            with tempfile.TemporaryFile() as tmp_file:
                await self.read_stream_to_file(request, tmp_file)
                with zipfile.ZipFile(tmp_file, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
            self.logger.info("Unzipped to %s", temp_dir)
            res = self.api.api_post_file(api_request, pathlib.Path(temp_dir))
        return res

    async def handle_ws(self, request):
        """Handle websocket HTTP request"""
        assert request.path_qs.startswith("/api1/ws/")
        req = APIRequest.parse(request.path_qs[9:])
        self.logger.info("WS: %s", req)
        if req.path != "model/subscribe":  # the only function
            return web.Response(status=404)
        req = req.change_path(".")  # we can only subscribe all

        ws = web.WebSocketResponse()
        await ws.prepare(request)

        try:
            self.check_permission(request)
        except PermissionError:
            # no permission to proceed, communicate error using WS
            await ws.close(code=4401, message=b"Permission check failed")  # 4000 + HTTP code
            self.logger.warning('Permission check failed')
            return

        self.logger.info('WS loop started')

        session = Session(self, ws, req)
        # initial model
        # do not async so that no updates between getting model and putting it to the queue
        session.subscribed = True
        if req.parameters.get("load_all", "").lower() != "false":  # can avoid JSON dump for debugging
            self.dump_model(session)
        self.sessions.append(session)

        async def receive_loop():
            # we expect nothing from client
            while True:
                msg = await ws.receive()
                if msg.type == WSMsgType.CLOSE:
                    self.logger.info("WS close")
                    break
                self.logger.warning("Unexpected WS type %d", msg.type)
        try:
            await receive_loop()
        finally:
            session.close()  # drop remaining sends
            self.sessions.remove(session)
        return ws

    def dump_model(self, session: Session):
        """Dump the whole model into a session"""
        if not session.subscribed:
            return
        for d in self.api.api_iterate_all(session.original_request):
            self.send_queue.put_nowait((session, d))

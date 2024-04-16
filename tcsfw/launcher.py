"""Lauch model given from command-line"""

import asyncio
import hmac
import json
import logging
import os
import argparse
import subprocess
import sys
import traceback
from typing import Dict, Set

import aiofiles
from aiohttp import web

class Launcher:
    """Lister for requests and launch models as separate processes"""
    def __init__(self):
        parser = argparse.ArgumentParser(description='Launcher script')
        parser.add_argument("--listen-port", "-p", type=int,
                            help="Listen HTTP requests at port")
        parser.add_argument("--launch", "-L", action="append", 
                            help="Launch applications instantly without starting service")
        parser.add_argument("-l", "--log", dest="log_level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                            help="Set the logging level", default=None)
        args = parser.parse_args()

        self.logger = logging.getLogger("launcher")
        logging.basicConfig(format='%(message)s', level=getattr(logging, args.log_level or 'INFO'))

        launch_apps = args.launch or []

        self.client_port_range = (10000, 11000)
        self.clients: Set[int] = set()
        self.connected: Dict[str, Dict] = {}

        self.host = None
        self.port = int(args.listen_port or 8180)  # match http server default port
        self.auth_token = os.environ.get("TCSFW_SERVER_API_KEY", "")
        if launch_apps:
            # test launch
            self.loop = asyncio.get_event_loop()
            for app in launch_apps:
                js_out = self.loop.run_until_complete(self.run_process("localhost", app))
                self.logger.info(json.dumps(js_out))
            self.loop.run_forever()
            return
        if not self.auth_token:
            raise ValueError("No environment variable TCSFW_SERVER_API_KEY")
        self.loop = asyncio.get_event_loop()
        self.run()

    def run(self):
        """Start sync loop and run the server"""
        self.loop.run_until_complete(self.start_server())
        self.loop.run_forever()

    async def start_server(self):
        """Start the Web server"""
        app = web.Application()
        app.add_routes([
            web.get('/connect/{tail:.+}', self.handle_http),
        ])
        rr = web.AppRunner(app)
        await rr.setup()
        site = web.TCPSite(rr, self.host, self.port)
        self.logger.info("HTTP server running at %s:%s...", self.host or "*", self.port)
        await site.start()

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
            if request.method != "GET":
                raise NotImplementedError("Unexpected method")
            assert request.path.startswith("/connect/")
            host = request.headers.get("Host", "localhost")
            host = host.split(":")[0]
            app = request.path[9:] + ".py"
            res = await self.run_process(host, app)
            return web.json_response(res)
        except NotImplementedError:
            return web.Response(status=400)
        except FileNotFoundError:
            return web.Response(status=404)
        except PermissionError:
            return web.Response(status=401)
        except Exception:  # pylint: disable=broad-except
            traceback.print_exc()
            return web.Response(status=500)

    async def run_process(self, host: str, app: str) -> Dict:
        """Run process by request"""
        known = self.connected.get(app)
        if known:
            return known  # already running

        client_port = None
        for port in range(*self.client_port_range):
            if port not in self.clients:
                client_port = port
                break
        else:
            raise FileNotFoundError("No free ports available")
        self.clients.add(client_port)
        res = self.connected[app] = {"host": f"{host}:{client_port}"}

        # schedule process execution by asyncio and return the port
        process = await asyncio.create_subprocess_exec(
            sys.executable, app, "--http-server", f"{client_port}",
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout_file = f'stdout-{client_port}.log'
        stderr_file = f'stderr-{client_port}.log'
        stdout_task = asyncio.create_task(self.save_stream_to_file(process.stdout, stdout_file))
        stderr_task = asyncio.create_task(self.save_stream_to_file(process.stderr, stderr_file))

        async def wait_process():
            await process.wait()
            await stdout_task
            await stderr_task
            self.clients.remove(client_port)
            self.connected.pop(app)
            self.logger.info("Exit code %s from %s at port %s", process.returncode, app, client_port)
            # remove log files
            os.remove(stdout_file)
            os.remove(stderr_file)

        asyncio.create_task(wait_process())

        self.logger.info("Launched %s at port %s", app, client_port)
        return res

    async def save_stream_to_file(self, stream, file_path):
        """Save data from stream to a file asynchronously"""
        async with aiofiles.open(file_path, 'wb') as f:
            while True:
                chunk = await stream.read(64 * 1024)
                if not chunk:
                    break
                await f.write(chunk)

if __name__ == "__main__":
    Launcher()

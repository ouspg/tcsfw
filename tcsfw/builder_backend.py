
import argparse
import json
import logging
import pathlib
import sys
from tcsfw.address import DNSName, IPAddress
from tcsfw.batch_import import BatchImporter, LabelFilter
from tcsfw.claim_coverage import RequirementClaimMapper
from tcsfw.client_api import APIRequest
from tcsfw.coverage_result import CoverageReport
from tcsfw.http_server import HTTPServerRunner
from tcsfw.latex_output import LaTeXGenerator
from tcsfw.main import DHCP, DNS, Builder
from tcsfw.model import Host
from tcsfw.registry import Registry
from tcsfw.inspector import Inspector
from tcsfw.result import Report
from tcsfw.visualizer import VisualizerAPI

class SystemBackend(Builder):
    """Backend for system builder"""
    def __init__(self, name: str):
        super().__init__(name)


    """Model builder and runner"""
    def __init__(self, name="Unnamed system"):
        super().__init__(name)
        parser = argparse.ArgumentParser()
        parser.add_argument("--read", "-r", action="append", help="Read tool output from batch directories")
        parser.add_argument("--help-tools", action="store_true", help="List tools read from batch")
        parser.add_argument("--def-loads", "-L", type=str, help="Comma-separated list of tools to load")
        parser.add_argument("--set-ip", action="append", help="Set DNS-name for entity, format 'name=ip, ...'")
        parser.add_argument("--output", "-o", help="Output format")
        parser.add_argument("--dhcp", action="store_true", help="Add default DHCP server handling")
        parser.add_argument("--dns", action="store_true", help="Add default DNS server handling")
        parser.add_argument("-l", "--log", dest="log_level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                            help="Set the logging level", default=None)

        parser.add_argument("--http-server", type=int, help="Listen HTTP requests at port")
        parser.add_argument("--test-delay", type=int, help="HTTP request artificial test delay, ms")
        parser.add_argument("--no-auth-ok", action="store_true", help="Skip check for auth token in TCSFW_SERVER_API_KEY")

        parser.add_argument("--test-get", action="append", help="Test API GET, repeat for many")
        parser.add_argument("--test-post", nargs=2, help="Test API POST")

        parser.add_argument("--log-events", action="store_true", help="Log events")

        self.parser = parser
        self.args = parser.parse_args()
        logging.basicConfig(format='%(message)s', level=getattr(logging, self.args.log_level or 'INFO'))

    def run(self):
        """Model is ready, run the checks"""
        if self.args.dhcp:
            self.any().serve(DHCP)
        if self.args.dns:
            self.any().serve(DNS)

        self.finish_()

        registry = Registry(Inspector(self.system))
        cc = RequirementClaimMapper(self.system)

        log_events = self.args.log_events
        if log_events:
            # print event log
            registry.logging.event_logger = registry.logger

        for set_ip in self.args.set_ip or []:
            name, _, ips = set_ip.partition("=")
            h = self.system.get_entity(name) or self.system.get_endpoint(DNSName.name_or_ip(name))
            if not isinstance(h, Host) or not h.is_relevant():
                raise ValueError(f"No such host '{name}'")
            for ip in ips.split(","):
                self.system.learn_ip_address(h, IPAddress.new(ip))

        label_filter = LabelFilter(self.args.def_loads or "")
        batch_import = BatchImporter(registry, filter=label_filter)
        for in_file in self.args.read or []:
            batch_import.import_batch(pathlib.Path(in_file))

        if self.args.help_tools:
            # print help and exit
            for label, sl in sorted(batch_import.evidence.items()):
                sl_s = ", ".join(sorted(set([s.name for s in sl])))
                print(f"{label:<20} {sl_s}")
            return

        # product claims, then explicit loaders (if any)
        for sub in self.claimSet.finish_loaders():
            sub.load(registry, cc, filter=label_filter)
        for ln in self.loaders:
            for sub in ln.subs:
                sub.load(registry, cc, filter=label_filter)

        api = VisualizerAPI(registry, cc, self.visualizer)
        dump_report = True
        if self.args.test_post:
            res, data = self.args.test_post
            resp, _ = api.api_post(APIRequest(res), io.BytesIO(data))
            print(json.dumps(resp, indent=4))
            dump_report = False
        if self.args.test_get:
            for res in self.args.test_get:
                print(json.dumps(api.api_get(APIRequest.parse(res)), indent=4))
                dump_report = False

        out_form = self.args.output
        if out_form and out_form.startswith("coverage"):
            cmd, _, spec_id = out_form.partition(":")
            cmd = cmd[8:]
            report = CoverageReport(registry.logging, cc)
            spec = report.load_specification(spec_id)
            report.print_summary(sys.stdout, spec, cmd.strip("- "))
        elif out_form and out_form.startswith("latex"):
            cmd, _, spec_id = out_form.partition(":")
            cmd = cmd[5:]
            spec = CoverageReport.load_specification(spec_id)
            report = LaTeXGenerator(self.system, spec, cc)
            report.generate(sys.stdout, cmd.strip(" -"))
        elif dump_report or out_form:
            report = Report(registry)
            if out_form in {'text', '', None}:
                report.print_report(sys.stdout)
            elif out_form == 'table-csv':
                report.tabular(sys.stdout)
            elif out_form == 'table-latex':
                report.tabular(sys.stdout, latex=True)
            else:
                raise Exception(f"Unknown output format '{out_form}'")

        if self.args.http_server:
            server = HTTPServerRunner(api, port=self.args.http_server, no_auth_ok=self.args.no_auth_ok)
            server.component_delay = (self.args.test_delay or 0) / 1000
            server.run()

        # # artificial connections for testing after pcaps, so that HW <-> IP resolved
        # for cn in self.args.connection or []:
        #     t_parser.add_artificial_connection(cn)
        # elif self.args.uml:
        #     print(PlantUMLRenderer().render(t_parser.system))
        # else:
        #     print(t_parser.inspector.print_summary(self.args.log_level == 'DEBUG'))

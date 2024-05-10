"""Text tables"""

from io import StringIO
from typing import Any, List, TextIO, Tuple

from tcsfw.model import Host, IoTSystem, NetworkNode, Service


class BaseTable:
    """Table base class"""
    def __init__(self, columns: List[Tuple[str, int]], screen_size: Tuple[int, int]):
        self.screen_size = screen_size
        self.columns = columns
        # spread columns evenly
        min_wid = sum([c[1] for c in columns])
        if min_wid < screen_size[0]:
            ratio = screen_size[0] / min_wid
            self.columns = [(c[0], int(c[1] * ratio)) for c in columns]

    def print(self, stream: TextIO):
        """Print!"""
        raise NotImplementedError()

    def print_rows(self, rows: List[List[Any]], stream: TextIO) -> str:
        """Print the rows"""
        for row in rows:
            line = []
            x, target_x = 0, 0
            assert len(row) == len(self.columns), f"Row and columns mismatch: {len(row)} != {len(self.columns)}"
            for i, col in enumerate(row):
                s = f"{col}"
                if i < len(self.columns) - 1:
                    s += ","
                col_wid = self.columns[i][1]
                target_x += col_wid
                pad_len = max(0, target_x - x - len(s))
                s = s + " " * pad_len
                line.append(s)
                x += len(s)
                # space between columns
                target_x += 1
                x += 1

            line_s = "".join(line)
            stream.write(f"{line_s}\n")


class HostTable(BaseTable):
    """Host table"""
    def __init__(self, root: IoTSystem, screen_size=(80, 50)):
        super().__init__([
            ("Host", 10),
            ("Service", 10),
            ("Component", 10),
        ], screen_size)
        self.root = root

    def print(self, stream: TextIO):
        rows = [[h[0] for h in self.columns]]

        def _components(node: NetworkNode):
            for c in node.components:
                rows.append(['', '', c.name])

        for h in self.root.get_children():
            if isinstance(h, Host):
                rows.append([h.long_name(), '', ''])
                _components(h)
                for s in h.get_children():
                    if isinstance(s, Service):
                        rows.append(['', s.long_name(), ''])
                        _components(s)

        self.print_rows(rows, stream)


class TableView:
    """View of one or more tables"""
    def __init__(self, tables: List[BaseTable]) -> None:
        self.tables = tables

    @classmethod
    def get_print(cls, model: IoTSystem, _name: str) -> str:
        """Get printout by name"""
        view = TableView([HostTable(model)])
        buf = StringIO()
        view.print(buf)
        return buf.getvalue()

    def print(self, stream: TextIO):
        """Print all tables"""
        for t in self.tables:
            t.print(stream)

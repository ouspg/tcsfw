# Short DSL intro

The framework uses _Domain Specific Language_ (DSL) to describe the system model.
The DSL is based on Python 3 programming language.
The following assumes basic understanding of the Python language.

## DSL essential

Consider the following very simple model called "Basic a".
The model is in file `samples/basic-a/system.py`.

```python
from tcsfw.main import Builder, TLS
from tcsfw.traffic import IPFlow

system = Builder.new("Basic A")
device = system.device()
backend = system.backend().serve()
app = system.mobile()

device >> backend / TLS
app >> backend / TLS
```

The model building start with call to `Builder.new`, which takes the name of the system as argument, and returns to system object.
The system comprises IoT _device_, _backend_ service, and a mobile _application_. 
The device and the application connect to the backend using TLS-protected connections.


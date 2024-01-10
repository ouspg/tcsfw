from tcsfw.main import Builder, TLS

system = Builder("IoT A")
device = system.device()
backend = system.backend().serve(TLS(auth=True))
app = system.mobile()

device >> backend / TLS
app >> backend / TLS

if __name__ == "__main__":
    system.run()

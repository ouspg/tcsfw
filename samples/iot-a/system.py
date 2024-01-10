from tcsfw.main import Builder, TLS

system = Builder("IoT A")
device = system.device()
backend = system.backend().serve(TLS(auth=True))
app = system.mobile()

device >> backend / TLS
app >> backend / TLS

# Visualization
system.visualize().place(
    "D   A",
    "  B  ",
) .where({
    "D": device,
    "B": backend,
    "A": app
})

if __name__ == "__main__":
    system.run()

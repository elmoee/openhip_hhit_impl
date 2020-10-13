# Running
Scripts must be executed within the core python virtual environment. It is
recommended to use the executable installed with core to start this. Note
that most scripts include editing network interfaces, which require super-user
privileges.
```bash
sudo core-python test_hip.py
```
Also note that core-daemon does NOT have to be running.

# Developing
To fully enjoy the capabilities your IDE provides, you must correctly setup the
`PYTHONPATH` environment variable. This should include the directory in which
core was compiled. As an example, to properly setup VSCode a file with the
following contents named `.env` is sufficient:
```
PYTHONPATH=...path_to_core.../daemon
```
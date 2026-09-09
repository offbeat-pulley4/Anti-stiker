import tempfile, os
def get_files_dir():
    d = os.path.join(tempfile.gettempdir(), "antistiker_test_files")
    os.makedirs(d, exist_ok=True)
    return d


def build_remote_read_command(path, begin_marker, end_marker, shell_type="linux"):
    if shell_type == "windows":
        return f"echo {begin_marker} & type \"{path}\" & echo {end_marker}"
    return f"echo {begin_marker}; cat \"{path}\"; echo {end_marker}"

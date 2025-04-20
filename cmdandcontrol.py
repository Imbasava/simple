# C2 Traffic Detector for Raspberry Pi
# This script reads network traffic logs, extracts relevant features, and uses
# the trained TensorFlow Lite model to detect Command & Control traffic in real-time

import os
import time
import numpy as np
import pandas as pd
import tflite_runtime.interpreter as tflite
import joblib
from datetime import datetime
import subprocess
import re

# Configuration
MODEL_PATH = "command_control_model.tflite"
ENCODER_PATH = "c2_encoder.pkl"
LOG_PATH = "/var/log/network_traffic.log"  # Path to your network logs
SCAN_INTERVAL = 5  # Seconds between log checks
ALERT_THRESHOLD = 0.7  # Higher confidence threshold for demo

class C2Detector:
    def __init__(self, model_path, encoder_path):
        """Initialize the C2 traffic detector with model and encoder."""
        print("[+] Initializing C2 Traffic Detector...")
        
        # Load TFLite model
        self.interpreter = tflite.Interpreter(model_path=model_path)
        self.interpreter.allocate_tensors()
        
        # Get input and output details
        self.input_details = self.interpreter.get_input_details()
        self.output_details = self.interpreter.get_output_details()
        
        # Load encoder for categorical features
        self.encoder = joblib.load(encoder_path)
        
        # Define allowed categories (must match training)
        self.allowed_categories = {
            0: ['tcp', 'udp', 'icmp', 'Unknown'],       # proto
            1: ['Unknown', 'http', 'dns', 'ssh', 'ftp', 'irc', 'ssl'],  # service
            2: ['S0', 'SF', 'REJ', 'OTH', 'S1', 'RSTO', 'RSTR', 'RSTOS0'], # conn_state
            3: ['S', 'SA', 'A', 'OTH', 'F', 'PA', 'FA', 'D', 'DF']      # history
        }
        
        print("[+] Detector initialized and ready!")
    
    def preprocess_connection(self, features):
        """
        Preprocess raw connection features for model input.
        
        Args:
            features: Dict with keys ['proto', 'service', 'duration', 'orig_bytes', 
                                      'conn_state', 'history', 'orig_pkts']
        Returns:
            Processed numpy array ready for model input
        """
        try:
            # Extract and convert numeric features
            duration = self._safe_float_convert(features.get('duration', 0))
            orig_bytes = self._safe_float_convert(features.get('orig_bytes', 0))
            orig_pkts = self._safe_float_convert(features.get('orig_pkts', 0))
            
            # Create numeric features array
            numeric = np.array([duration, orig_bytes, orig_pkts], dtype=np.float32)
            
            # Extract categorical features
            proto = str(features.get('proto', 'Unknown')).lower()
            service = str(features.get('service', 'Unknown')).lower()
            conn_state = str(features.get('conn_state', 'OTH'))
            history = str(features.get('history', 'OTH'))
            
            # Clean categorical values
            cat_values = [proto, service, conn_state, history]
            cleaned_cat = []
            
            # Ensure categorical values are in allowed categories
            for idx, val in enumerate(cat_values):
                if val not in self.allowed_categories[idx]:
                    if idx == 0:
                        val = 'Unknown'
                    elif idx == 1:
                        val = 'Unknown'
                    elif idx == 2 or idx == 3:
                        val = 'OTH'
                cleaned_cat.append(val)
            
            # Apply one-hot encoding
            cat_features = np.array([cleaned_cat])
            encoded_cat = self.encoder.transform(cat_features).toarray()
            
            # Combine features
            combined = np.hstack([numeric, encoded_cat]).astype(np.float32)
            return combined
            
        except Exception as e:
            print(f"[-] Error preprocessing connection: {e}")
            # Return safe default features in case of processing error
            dummy_features = np.zeros((1, 31), dtype=np.float32)  # Match feature count from training
            return dummy_features
    
    def _safe_float_convert(self, value):
        """Safely convert value to float, handling various formats and errors."""
        try:
            if value is None or value == '-' or value == '':
                return 0.0
            return float(value)
        except (ValueError, TypeError):
            return 0.0
    
    def detect(self, connection_features):
        """
        Detect if a connection has C2 characteristics.
        
        Args:
            connection_features: Dict with connection information
            
        Returns:
            Dict with detection results
        """
        # Preprocess the features
        preprocessed = self.preprocess_connection(connection_features)
        
        # Reshape for the model (batch size of 1)
        input_data = preprocessed.reshape(1, preprocessed.shape[0])
        
        # Set the input tensor
        self.interpreter.set_tensor(self.input_details[0]['index'], input_data)
        
        # Run inference
        self.interpreter.invoke()
        
        # Get prediction
        risk_score = float(self.interpreter.get_tensor(self.output_details[0]['index'])[0][0])
        
        return {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "is_c2": risk_score > 0.5,
            "high_confidence": risk_score > ALERT_THRESHOLD,
            "risk_score": risk_score,
            "status": "MALICIOUS" if risk_score > 0.5 else "BENIGN",
            "details": connection_features
        }

class LogParser:
    """Class to parse network logs into features for the C2 detector."""
    
    def __init__(self):
        self.last_processed_line = 0
        
    def parse_tcpdump_output(self, line):
        """Parse tcpdump output into connection features."""
        try:
            # Example tcpdump line: 10:15:45.123456 IP 192.168.1.100.12345 > 10.0.0.1.80: TCP flags [S]
            
            # Extract basic connection info using regex
            ip_pattern = r'(\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+)'
            protocol_pattern = r': (\w+)'
            flags_pattern = r'flags \[([^\]]+)\]'
            
            ip_match = re.search(ip_pattern, line)
            proto_match = re.search(protocol_pattern, line)
            flags_match = re.search(flags_pattern, line)
            
            if not ip_match:
                return None
                
            # Extract matched information
            src_ip = ip_match.group(1)
            src_port = ip_match.group(2)
            dst_ip = ip_match.group(3)
            dst_port = ip_match.group(4)
            proto = proto_match.group(1).lower() if proto_match else 'unknown'
            
            # Map TCP flags to history format similar to Zeek
            history = 'OTH'
            if flags_match:
                flags = flags_match.group(1)
                if 'S' in flags and 'A' in flags:
                    history = 'SA'
                elif 'S' in flags:
                    history = 'S'
                elif 'A' in flags:
                    history = 'A'
                elif 'F' in flags:
                    history = 'F'
                elif 'R' in flags:
                    history = 'R'
            
            # Determine service based on common ports
            service = 'unknown'
            dst_port_num = int(dst_port) if dst_port.isdigit() else 0
            if dst_port_num == 80 or dst_port_num == 8080:
                service = 'http'
            elif dst_port_num == 443:
                service = 'ssl'
            elif dst_port_num == 53:
                service = 'dns'
            elif dst_port_num == 22:
                service = 'ssh'
            elif dst_port_num == 21:
                service = 'ftp'
            elif dst_port_num == 6667:
                service = 'irc'
            
            # Create connection object with inferred values
            connection = {
                'proto': proto,
                'service': service,
                'duration': 0,  # Can't determine from single packet
                'orig_bytes': 0,  # Can't determine reliably
                'conn_state': 'OTH',  # Default
                'history': history,
                'orig_pkts': 1,  # Single packet
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port
            }
            
            return connection
            
        except Exception as e:
            print(f"[-] Error parsing tcpdump line: {e}")
            return None
    
    def get_new_connections(self, log_file=None):
        """
        Get new connections from log file or generate from live capture
        Returns list of connection feature dictionaries
        """
        connections = [] 

        try:
            # Use tcpdump to capture a small sample of live traffic
            cmd = ["sudo", "tcpdump", "-c", "10", "-n"]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            output, _ = process.communicate()
                
            for line in output.decode('utf-8').splitlines():
                conn = self.parse_tcpdump_output(line)
                if conn:
                    connections.append(conn)
                        
        except Exception as e:
            print(f"[-] Error capturing live traffic: {e}")
        
        return connections

def display_alert(result):
    """Display an alert for detected C2 traffic."""
    if result["high_confidence"]:
        alert = f"""
╔══════════════════════════════════════════════════╗
║ 🚨 HIGH CONFIDENCE C2 TRAFFIC DETECTED! 🚨       ║
╠══════════════════════════════════════════════════╣
║ Time: {result['timestamp']}                      ║
║ Risk Score: {result['risk_score']:.4f}           ║
║ Source: {result['details']['src_ip']}:{result['details']['src_port']} ║
║ Destination: {result['details']['dst_ip']}:{result['details']['dst_port']} ║
║ Protocol: {result['details']['proto']}           ║
║ Service: {result['details']['service']}          ║
╚══════════════════════════════════════════════════╝
"""
        print(alert)
    elif result["is_c2"]:
        print(f"[!] Potential C2 detected: {result['risk_score']:.4f} confidence - {result['details']['src_ip']} → {result['details']['dst_ip']}")

def main():
    """Main function to run the C2 detector."""
    print("╔═════════════════════════════════════════════╗")
    print("║ Raspberry Pi Command & Control Traffic      ║")
    print("║ Real-time Detection System                  ║")
    print("╚═════════════════════════════════════════════╝")
    
    # Initialize detector and log parser
    try:
        detector = C2Detector(MODEL_PATH, ENCODER_PATH)
        parser = LogParser()
        
        print(f"[+] Monitoring for Command & Control traffic...")
        print(f"[+] Alert threshold set to {ALERT_THRESHOLD}")
        print(f"[+] Checking for new connections every {SCAN_INTERVAL} seconds")
        
        # Track statistics
        stats = {
            "connections_analyzed": 0,
            "alerts_generated": 0,
            "start_time": time.time()
        }
        
        # Main monitoring loop
        while True:
            # Get new connections
            connections = parser.get_new_connections()
            
            if connections:
                print(f"[+] Processing {len(connections)} new connections")
                
                # Process each connection
                for conn in connections:
                    # Detect C2 traffic
                    result = detector.detect(conn)
                    stats["connections_analyzed"] += 1
                    
                    # Display results
                    if result["is_c2"]:
                        stats["alerts_generated"] += 1
                        display_alert(result)
                
                # Print stats periodically
                runtime = time.time() - stats["start_time"]
                if stats["connections_analyzed"] % 50 == 0:
                    print(f"[+] Stats: Analyzed {stats['connections_analyzed']} connections, "
                          f"Generated {stats['alerts_generated']} alerts, "
                          f"Running for {runtime:.1f} seconds")
            
            # Wait before next check
            time.sleep(SCAN_INTERVAL)
            
    except KeyboardInterrupt:
        runtime = time.time() - stats["start_time"]
        print("\n[+] Detection stopped by user")
        print(f"[+] Final stats: Analyzed {stats['connections_analyzed']} connections, "
              f"Generated {stats['alerts_generated']} alerts, "
              f"Ran for {runtime:.1f} seconds")
    except Exception as e:
        print(f"[-] Error in main detection loop: {e}")

if __name__ == "__main__":
    main()
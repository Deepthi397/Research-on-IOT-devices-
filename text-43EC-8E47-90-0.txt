import tkinter as tk
from tkinter import ttk, scrolledtext
import re
import urllib.request
import urllib.error
from datetime import datetime
import time
import json
import threading

class RequestSenderApp(tk.Tk):
    """
    A desktop GUI application built with Tkinter that allows a user to send
    a mock subscription request to a device IP, port, and URL.
    """
    def __init__(self):
        super().__init__()

        # --- Window Setup ---
        self.title("Mock Request Sender")
        self.geometry("600x450")
        self.resizable(False, False) # Make window not resizable
        self.configure(bg='#f0f0f0') # Set a light grey background

        # --- Style Configuration ---
        style = ttk.Style(self)
        style.configure('TLabel', background='#f0f0f0', font=('Helvetica', 10))
        style.configure('TButton', font=('Helvetica', 10, 'bold'))
        style.configure('TEntry', font=('Helvetica', 10))

        # --- Main Frame ---
        main_frame = ttk.Frame(self, padding="20 20 20 20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- UI Widget Creation ---
        self.create_widgets(main_frame)


    def create_widgets(self, container):
        """
        Creates and arranges all the UI widgets in the application window.
        """
        # --- Input Fields ---
        # IP Address
        ttk.Label(container, text="Device IP:").grid(row=0, column=0, sticky="w", pady=5)
        self.ip_input = ttk.Entry(container, width=40)
        self.ip_input.insert(0, "192.168.1.1")
        self.ip_input.grid(row=0, column=1, sticky="ew", pady=5)

        # Port
        ttk.Label(container, text="Port:").grid(row=1, column=0, sticky="w", pady=5)
        self.port_input = ttk.Entry(container, width=40)
        self.port_input.insert(0, "80")
        self.port_input.grid(row=1, column=1, sticky="ew", pady=5)

        # Subscription URL
        ttk.Label(container, text="Subscription URL:").grid(row=2, column=0, sticky="w", pady=5)
        self.url_input = ttk.Entry(container, width=40)
        self.url_input.insert(0, "http://device/subscribe")
        self.url_input.grid(row=2, column=1, sticky="ew", pady=5)

        # --- Submit Button ---
        self.submit_button = ttk.Button(
            container,
            text="Send Request",
            command=self.on_submit_clicked
        )
        self.submit_button.grid(row=3, column=1, sticky="e", pady=15)

        # --- Output Area ---
        ttk.Label(container, text="Response:").grid(row=4, column=0, sticky="w", pady=5)
        self.output_text = scrolledtext.ScrolledText(
            container,
            wrap=tk.WORD,
            width=60,
            height=12,
            font=("Courier New", 10),
            state='disabled' # Start as read-only
        )
        self.output_text.grid(row=5, column=0, columnspan=2, sticky="ew")

        # Configure grid column weights to make entry fields expand
        container.columnconfigure(1, weight=1)

    def validate_inputs(self, ip, port, url):
        """
        Validates the user's input for IP, port, and URL.
        Returns a tuple (bool, str) of (is_valid, error_message).
        """
        # Validate IP address format
        ip_regex = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(ip_regex, ip):
            return False, 'Invalid IP address format.'

        # Validate Port
        if not port.isdigit() or not (1 <= int(port) <= 65535):
            return False, 'Port must be a number between 1 and 65535.'

        # Validate URL format
        if not url.startswith(('http://', 'https://')):
             return False, 'Invalid URL format (must start with http:// or https://).'

        return True, ''

    def update_output(self, message):
        """
        Thread-safe method to update the output text area.
        """
        self.output_text.config(state='normal') # Enable writing
        self.output_text.delete('1.0', tk.END)
        self.output_text.insert(tk.END, message)
        self.output_text.config(state='disabled') # Disable writing

    def process_request_thread(self, ip, port, url):
        """
        This function runs in a separate thread to avoid freezing the GUI.
        It validates inputs, simulates a delay, and prepares the response.
        """
        # 1. Validate inputs
        is_valid, message = self.validate_inputs(ip, port, url)
        if not is_valid:
            self.update_output(f'❌ Error: {message}')
            return # End thread execution

        # 2. Simulate processing delay
        time.sleep(1.5)

        # 3. Create the mock response
        mock_response = {
            "status": "success",
            "data": {
                "ip": ip,
                "port": port,
                "subscriptionUrl": url,
                "timestamp": datetime.now().isoformat(),
                "message": "Subscription request processed successfully"
            }
        }
        
        # 4. Format the response as a pretty-printed JSON string
        response_str = json.dumps(mock_response, indent=4)
        final_message = "✅ Response Received:\n\n" + response_str
        
        # 5. Schedule the GUI update on the main thread
        self.after(0, self.update_output, final_message)

    def on_submit_clicked(self):
        """
        Handles the click event for the 'Send Request' button.
        Starts a new thread to process the request.
        """
        # Get values from the input fields
        ip = self.ip_input.get()
        port = self.port_input.get()
        url = self.url_input.get()

        # Update the UI immediately to show processing has started
        self.update_output("⏳ Processing request...")

        # Create and start a new thread to handle the request.
        # This prevents the GUI from freezing during the time.sleep() call.
        thread = threading.Thread(
            target=self.process_request_thread,
            args=(ip, port, url)
        )
        thread.daemon = True  # Allows main window to exit even if thread is running
        thread.start()


if __name__ == "__main__":
    # Create and run the application
    app = RequestSenderApp()
    app.mainloop()

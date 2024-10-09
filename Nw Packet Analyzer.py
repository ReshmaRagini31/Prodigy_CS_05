import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff

class PacketAnalyzer(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Network Packet Analyzer")
        self.geometry("600x400")

        self.start_button = tk.Button(self, text="Start Capturing", command=self.start_capturing)
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(self, text="Stop Capturing", command=self.stop_capturing, state=tk.DISABLED)
        self.stop_button.pack(pady=10)

        self.output_area = scrolledtext.ScrolledText(self, wrap=tk.WORD)
        self.output_area.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        self.capturing = False

    def start_capturing(self):
        self.capturing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.output_area.delete(1.0, tk.END)
        self.sniff_packets()

    def stop_capturing(self):
        self.capturing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self):
        if self.capturing:
            sniff(prn=self.process_packet, count=1)  # Capture one packet at a time
            self.after(100, self.sniff_packets)      # Schedule the next capture

    def process_packet(self, packet):
        packet_info = f"Packet: {packet.summary()}\n"
        self.output_area.insert(tk.END, packet_info)
        self.output_area.see(tk.END)  # Scroll to the end

if __name__ == "__main__":
    app = PacketAnalyzer()
    app.mainloop()

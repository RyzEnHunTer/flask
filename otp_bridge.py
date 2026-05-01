"""
Shared OTP state between Flask (app_premium.py) and pyquotex (login.py).
Both modules import from here so they share the SAME queue object.
"""
import queue

otp_needed = False    # True when login is waiting for OTP
otp_prompt = ""       # The prompt message from Quotex
otp_queue  = queue.Queue()  # Web UI puts the code here

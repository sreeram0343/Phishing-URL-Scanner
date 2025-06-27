import customtkinter as ctk
from tkinter import messagebox
import threading
import sys

# --- Conditional Imports for External Libraries ---
# This block attempts to import necessary libraries. If any are missing,
# it sets a flag and prepares an error message for the user.
try:
    import requests
    import validators
    import whois
    import tldextract
    # socket is a built-in module, so no need to handle ImportError for it
    _EXTERNAL_LIBS_AVAILABLE = True
except ImportError as e:
    _EXTERNAL_LIBS_AVAILABLE = False
    _MISSING_LIB = str(e).split(' ')[-1]
    # Use ctk.CTk() for the messagebox to ensure it uses the CustomTkinter theme
    # This assumes ctk is already imported, which it will be when the app starts
    ctk.CTk().withdraw() # Hide the root window temporarily for messagebox
    messagebox.showerror("Missing Libraries",
                         f"Missing required library: {_MISSING_LIB}\n"
                         "Please install it using:\n"
                         f"pip install {_MISSING_LIB}\n\n"
                         "Full list of required libraries:\n"
                         "pip install customtkinter requests validators python-whois tldextract\n\n"
                         "The application will still run, but core functionality might be limited.")
    ctk.CTk().destroy() # Close the temporary window


# --- Scanner Functions ---
# These functions remain largely the same, but now check for library availability.

def is_shortened(url):
    """Checks if the given URL's domain is a common URL shortener."""
    if not _EXTERNAL_LIBS_AVAILABLE:
        return "N/A (Missing Libraries)"
    
    shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'buff.ly', 'adf.ly', 'bit.do']
    try:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        return domain in shorteners
    except Exception as e:
        return f"Error checking shortened URL: {e}"

def get_domain_age(domain):
    """Retrieves the creation date of a domain using WHOIS lookup."""
    if not _EXTERNAL_LIBS_AVAILABLE:
        return "N/A (Missing Libraries)"

    try:
        w = whois.whois(domain)
        if w.creation_date:
            # Handle list of dates if multiple are returned
            if isinstance(w.creation_date, list):
                return str(w.creation_date[0])
            return str(w.creation_date)
            
        else:
            return "No creation date found"
    except Exception as e:
        return f"WHOIS lookup failed: {e}"

def resolve_url(url):
    """Resolves a URL to its final destination after redirects."""
    if not _EXTERNAL_LIBS_AVAILABLE:
        return url # Cannot resolve if requests is missing
    
    try:
        # Allow redirects and set a timeout for the request
        response = requests.get(url, timeout=10, allow_redirects=True)
        return response.url
    except requests.exceptions.RequestException as e:
        return f"Could not resolve URL (Request Error): {e}"
    except Exception as e:
        return f"Could not resolve URL (Generic Error): {e}"

def check_phishtank(url):
    """Checks the URL against the PhishTank database."""
    if not _EXTERNAL_LIBS_AVAILABLE:
        return "N/A (Missing Libraries)"

    try:
        # Note: PhishTank API often requires an API key for robust use.
        # This basic check might not be reliable without one.
        # A more official API endpoint might be needed.
        # This example uses a simplified check that might be rate-limited or deprecated.
        api_url = f"http://checkurl.phishtank.com/checkurl/"
        headers = {'User-Agent': 'Mozilla/5.0'}
        data = {'url': url, 'format': 'json'} # PhishTank usually expects POST with form data
        response = requests.post(api_url, data=data, headers=headers, timeout=10)
        
        # PhishTank's checkurl endpoint is meant for querying their API via a key.
        # Without an API key, direct scraping of the checkurl page might be blocked or change.
        # For a proper integration, you'd register for an API key and use their official method.
        # This simplified check might not be reliable.
        if response.status_code == 200:
            if 'phishTank.com' in response.text or '"phish_id":' in response.text: # Simple check
                return "URL flagged as phishing (PhishTank)."
            return "URL not found in PhishTank."
        else:
            return f"PhishTank API returned status code {response.status_code}"
    except requests.exceptions.RequestException as e:
        return f"PhishTank check failed (Request Error): {e}"
    except Exception as e:
        return f"PhishTank check failed (Generic Error): {e}"

def scan_url_logic():
    """Contains the core scanning logic, to be run in a separate thread."""
    url = url_entry.get().strip()
    result_box.delete("1.0", ctk.END)
    loading_label.configure(text="Scanning... Please wait.")
    app.update_idletasks() # Update GUI immediately

    # Disable buttons during scan
    scan_btn.configure(state="disabled")
    clear_btn.configure(state="disabled")

    if not url:
        messagebox.showwarning("Input Error", "Please enter a URL to scan.")
        loading_label.configure(text="")
        scan_btn.configure(state="normal")
        clear_btn.configure(state="normal")
        return

    if not _EXTERNAL_LIBS_AVAILABLE:
        result_box.insert(ctk.END, "Cannot perform full scan due to missing libraries.\n")
        loading_label.configure(text="Scan aborted (Missing Libraries).")
        scan_btn.configure(state="normal")
        clear_btn.configure(state="normal")
        return

    if not validators.url(url):
        result_box.insert(ctk.END, "Invalid URL format. Please include http:// or https://\n")
        loading_label.configure(text="Scan finished (Invalid URL).")
        scan_btn.configure(state="normal")
        clear_btn.configure(state="normal")
        return

    result_box.insert(ctk.END, f"Scanning URL: {url}\n\n")
    app.update_idletasks()

    resolved_url = resolve_url(url)
    result_box.insert(ctk.END, f"Final resolved URL: {resolved_url}\n")
    app.update_idletasks()

    shortened = is_shortened(resolved_url)
    result_box.insert(ctk.END, f"Shortened URL: {'Yes' if shortened else 'No'}\n")
    app.update_idletasks()

    try:
        ext = tldextract.extract(resolved_url)
        domain = f"{ext.domain}.{ext.suffix}"
        result_box.insert(ctk.END, f"Domain: {domain}\n")
        app.update_idletasks()
        
        age_info = get_domain_age(domain)
        result_box.insert(ctk.END, f"Domain Age Info: {age_info}\n")
        app.update_idletasks()

    except Exception as e:
        result_box.insert(ctk.END, f"Error extracting domain/age: {e}\n")
        domain = "N/A" # Set domain to N/A if extraction fails

    phishtank_status = check_phishtank(resolved_url)
    result_box.insert(ctk.END, f"PhishTank: {phishtank_status}\n")
    app.update_idletasks()
    
    loading_label.configure(text="Scan Complete.")
    scan_btn.configure(state="normal")
    clear_btn.configure(state="normal")


def threaded_scan_start():
    """Starts the scanning logic in a new thread."""
    threading.Thread(target=scan_url_logic, daemon=True).start()

def clear_fields():
    """Clears the URL entry and the results text box."""
    url_entry.delete(0, ctk.END)
    result_box.delete("1.0", ctk.END)
    loading_label.configure(text="")

# --- GUI Setup ---
ctk.set_appearance_mode("System")  # Modes: "System", "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue", "dark-blue", "green"

app = ctk.CTk()
app.title("Phishing URL Scanner")
app.geometry("650x550")
app.resizable(False, False) # Keep fixed size for this simple layout

# Configure grid layout (1 column for main content)
app.grid_columnconfigure(0, weight=1)

# Title
title = ctk.CTkLabel(app, text="Phishing URL Scanner", 
                     font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"), 
                     text_color="#0984e3")
title.grid(row=0, column=0, pady=(25, 5), sticky="n")

subtitle = ctk.CTkLabel(app, text="Scan URLs for suspicious indicators like shorteners, domain age, and phishing flags.", 
                        font=ctk.CTkFont(family="Segoe UI", size=13), 
                        text_color="#636e72")
subtitle.grid(row=1, column=0, pady=(0, 20), sticky="n")

# URL Entry
url_entry = ctk.CTkEntry(app, placeholder_text="Enter URL (e.g., https://example.com)", 
                         width=450, height=40,
                         font=ctk.CTkFont(family="Segoe UI", size=14),
                         corner_radius=10, border_width=2,
                         border_color="#0984e3")
url_entry.grid(row=2, column=0, pady=(0, 15), ipady=5)

# Buttons Frame
button_frame = ctk.CTkFrame(app, fg_color="transparent") # Use transparent frame
button_frame.grid(row=3, column=0, pady=10)
button_frame.grid_columnconfigure(0, weight=1)
button_frame.grid_columnconfigure(1, weight=1)

scan_btn = ctk.CTkButton(button_frame, text="🔍 Scan URL", command=threaded_scan_start, 
                         font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"), 
                         width=150, height=40,
                         fg_color="#3498DB", hover_color="#2980B9",
                         corner_radius=10)
scan_btn.grid(row=0, column=0, padx=15, pady=5)

clear_btn = ctk.CTkButton(button_frame, text="🧹 Clear", command=clear_fields, 
                          font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"), 
                          width=150, height=40,
                          fg_color="#636e72", hover_color="#535c68",
                          corner_radius=10)
clear_btn.grid(row=0, column=1, padx=15, pady=5)

# Loading Indicator
loading_label = ctk.CTkLabel(app, text="", 
                             font=ctk.CTkFont(family="Segoe UI", size=12, slant="italic"),
                             text_color="#e67e22") # Orange for status
loading_label.grid(row=4, column=0, pady=(5, 10))

# Result Output
result_box = ctk.CTkTextbox(app, height=180, width=550, 
                            font=ctk.CTkFont(family="Consolas", size=12), 
                            wrap="word", 
                            corner_radius=10, border_width=2,
                            border_color="#ced4da", # Light grey border
                            scrollbar_button_color="#2980B9", # Scrollbar button color
                            scrollbar_button_hover_color="#3498DB") # Scrollbar hover color
result_box.grid(row=5, column=0, pady=(10, 15), padx=20, sticky="nsew")

# Footer
footer = ctk.CTkLabel(app, text="Developed by SREERAM M R for security needs", 
                      font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold", slant="italic"),
                      text_color="#34495e") # Darker color for bolder effect
footer.grid(row=6, column=0, pady=(5, 10), sticky="s")

# Check for missing libraries at startup
# This needs to be called AFTER the app object is created
if not _EXTERNAL_LIBS_AVAILABLE:
    app.after(100, lambda: messagebox.showerror("Missing Libraries",
                                                "Some required Python libraries are not installed.\n"
                                                "Please install them using pip:\n\n"
                                                "pip install customtkinter requests validators python-whois tldextract\n\n"
                                                "The application functionality will be limited until they are installed."))
    scan_btn.configure(state="disabled") # Disable scan if core libs are missing


app.mainloop()


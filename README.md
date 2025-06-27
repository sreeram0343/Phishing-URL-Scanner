🛡️ Phishing URL Scanner
A modern Python-based desktop application to detect and analyze potentially malicious or suspicious URLs. Built with a sleek CustomTkinter GUI, this tool combines multiple security heuristics and online threat intelligence to help users evaluate the safety of any URL in seconds.

🚀 Key Features
🔗 URL Resolution
• Automatically follows redirects and expands shortened URLs to reveal the final destination.

🔍 Shortened URL Detection
• Detects popular URL shorteners (e.g., bit.ly, tinyurl.com, t.co) which are often used in phishing campaigns.

📅 Domain Age Lookup
• Uses WHOIS to retrieve the domain's creation date and flags newly registered domains (commonly used by attackers).

🧠 PhishTank Threat Intelligence
• Checks the URL against the PhishTank database of reported phishing links. (⚠️ API key required for full integration.)

🖥️ Modern CustomTkinter Interface
• Built with CustomTkinter for a clean, user-friendly GUI with custom styling, hover effects, and responsive behavior.

⚙️ Asynchronous Scanning
• Runs scans on separate threads to ensure the app stays responsive during network operations.

🧪 Real-Time Feedback
• Color-coded output and detailed analysis of domain trustworthiness, HTTPS status, and URL patterns.

🧰 Technologies Used
Python 3.x

customtkinter – Stylish modern GUI

requests – HTTP requests and URL resolution

validators – Input validation

python-whois – Domain age and registration details

tldextract – Domain parsing

threading – Smooth multi-threaded GUI updates

📦 Installation & Setup
1. Clone the Repository
bash
Copy
Edit
git clone https://github.com/sreeram0343/Phishing-URL-Scanner.git
cd Phishing-URL-Scanner
2. Install Dependencies
Make sure Python 3 is installed. Then run:

bash
Copy
Edit
pip install customtkinter requests validators python-whois tldextract
3. Run the Application
Replace phishing_scanner_gui.py with your actual file name:

bash
Copy
Edit
python phishing_scanner.py
💡 How to Use
Launch the application.

Enter a URL in the input field.

Click the "Scan URL" button.

View the results, including:

Final resolved URL

Shortened URL detection

WHOIS domain age check

PhishTank match status

🔒 Important Notes
For full PhishTank functionality, you may need to register for an API key.

Always keep libraries updated for improved security and performance.

👨‍💻 Created by
Sreeram M R
B.Tech CSE Student | Cybersecurity Enthusiast
📧 sreerammurali2005@gmail.com

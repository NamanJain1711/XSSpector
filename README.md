XSSpector (This tool in Testing phase with few payloads please try to use your own custom payloads...within month we will launch our final tool with more funtions like file upload test ....thankyou)

XSSpector is a powerful and versatile tool designed to detect and exploit Cross-Site Scripting (XSS) vulnerabilities in web applications. With its advanced features and user-friendly interface, XSSpector is the perfect tool for security researchers, penetration testers, and developers who want to identify and remediate XSS vulnerabilities in their web applications.

Key Features:

    Advanced XSS Detection: XSSpector uses a combination of static and dynamic analysis techniques to detect XSS vulnerabilities in web applications.
    Customizable Payloads: Users can create and customize their own XSS payloads to test for vulnerabilities.
    Proxy Support: XSSpector supports proxy servers, allowing users to test web applications behind a proxy.
    Cookie Management: The tool allows users to manage cookies and session data, making it easy to test authenticated web applications.
    Colorful Output: XSSpector's output is colorful and easy to read, making it simple to identify vulnerabilities and understand the results.

Use Cases:

    Vulnerability Scanning: Use XSSpector to scan web applications for XSS vulnerabilities and identify potential security risks.
    Penetration Testing: XSSpector is a valuable tool for penetration testers who want to simulate real-world attacks and identify vulnerabilities in web applications.
    Development and Testing: Developers can use XSSpector to test their web applications for XSS vulnerabilities and ensure they are secure before deployment.

Requirements:

    Python 3.x: XSSpector requires Python 3.x to run.
    requests Library: The tool uses the requests library to send HTTP requests and interact with web applications.

Usage:

python xsspector.py [options]

Options:

    -u Target url (e.g. http://testphp.vulnweb.com)
    --depth Depth web page to crawl. Default: 2
    --payload-level Level for payload Generator, 1 for custom payload.  Default: 1
    --payload Load custom payload directly (e.g. <script>alert('Vigrahak')</script>)
    --payloads-file Load payloads from a file (e.g. payloads.txt)
    --method Method setting(s): \n\t0: GET\n\t1: POST\n\t2: GET and POST (default)
    --user-agent Request user agent (e.g. Chrome/2.1.1/...)
    --single Single scan. No crawling just one address")
    --proxy Set proxy (e.g. {'https':'https://10.10.1.10:1080'}
    --about Print information about XSS tool
    --cookie Set cookie (e.g {'ID=session')
    --fuzz Fuzz parameter URL (e.g. http://example.com/test?param=143)

Examples:

    python3 xsspector.py -u https://example.com
    python3 xsspector.py -u https://example.com --payloads-file xsspayloads.txt
    python3 xsspector.py -u https://example.com -p http://localhost:8080
    python3 xsspector.py -u https://example.com -c {"session_id": "1234567890"}
    python3 xsspector.py --fuzz "https://example.com/test?value=123" --payloads-file xsspayloads.txt

Installation

Prerequisites:

    Python 3.6 or later
    requests library (install with pip install requests)

Install XSSpector:

    Clone the XSSpector repository: git clone https://github.com/your-username/xsspector.git
    Change into the XSSpector directory: cd xsspector
    Install the required libraries: pip install -r requirements.txt
    Run XSSpector: python xsspector.py [options]

Note: Make sure to replace https://github.com/your-username/xsspector.git with the actual URL of your XSSpector repository.

![xz1](https://github.com/user-attachments/assets/baed817a-088b-444e-89d8-97f26e949089)
![xz2](https://github.com/user-attachments/assets/f98acc49-edf8-4bfa-b862-804e7a5067e6)

Let me know if you need any further modifications!
Contact: vigrahak1828@gmail.com
Donation: https://www.paypal.com/paypalme/SourrahS1828

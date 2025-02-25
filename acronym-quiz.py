"""
A quiz program that tests the user on their knowledge of the acronyms on the
Security+ exam.

The program begins by welcoming the user to the program.
It then asks the user which of two modes they would like to play in:
    1. Test on Acronyms
    2. Test on Definitions

If the user chooses mode 1, the program will display a definition and ask the
user to input the acronym that corresponds to the definition. If the user
chooses mode 2, the program will display an acronym and ask the user to input
the definition that corresponds to the acronym.

After the program gets the mode, it will ask the user how many questions they
would like to answer. They can choose to use the entire list of acronyms or
enter a number of questions they would like to answer, which will be randomly
selected from the list of acronyms.

The program will ask the user the questions and keep track of the number of
correct answers. Feedback will be given to the user after each question. If
the user gets the question correct, the program will display "Correct!" and
move on to the next question after incrementing the score. If the user gets
the question incorrect, the program will display "Incorrect! The correct
answer is: " and display the correct answer. Incorrect answers are saved to
be asked again at the end of the quiz.

After the quiz is over, the program will display the user's score and ask if
the user would like to review the questions they got incorrect. If the user
chooses to review the questions, the program will quiz the user on the
questions they got incorrect until they get them all correct. If the user
chooses not to review the questions, the program will display a message
thanking the user for playing the quiz.
"""

# Import the random module for generating random questions
import random
# Import the string module for striping punctuation
import string

# Constants for the different modes
ACRONYM_MODE = '1'
DEFINITION_MODE = '2'


def main():
    """
    This function holds the main logic of the program.
    """

    # Welcome the user to the program
    welcome()

    # Get the mode the user would like to play in
    # (Acronym mode or Definition mode)
    mode = get_mode()
    print()  # Print a newline for spacing

    # Get the number of questions the user would like to answer
    # (all or a specific number of questions)
    number_of_questions = get_number_of_questions(
        generate_acronym_dictionary())  # Acronym list is the arguement

    # Generate the questions to ask based on the user's input
    questions = generate_questions(number_of_questions)
    print()  # Print a newline for spacing

    # Quiz the user on the questions, get the score and incorrect questions
    score, incorrect_questions = quiz_user(questions, mode)

    # Display the user's score as a fraction and percent
    print(f"Your score: {score}/{len(questions)} " +
          f"({score/len(questions):.2%})\n")

    # Ask the user if they would like to review the
    # questions they got incorrect
    while ask_to_review_questions():  # while the user enters "Y" to review

        # Ask the incorrection questions
        review_incorrect_questions(incorrect_questions, mode)

        # Check if the user has answered all the questions correctly
        if not incorrect_questions:
            print("You have answered all the questions correctly!")
            break

    # Thank the user for playing the quiz
    print("\nThank you for playing the Acronym Quiz Program!")


def welcome():
    """
    This function welcomes the user to the program.
    """
    print("Welcome to the Acronym Quiz Program!")
    print("This program will test your knowledge of the acronyms on " +
          "the Security+ exam.")
    print("Let's get started!\n")


def get_mode():
    """
    This function asks the user which mode they would like to play in.
    It asks the user to input 1 for Acronym mode or 2 for Definition mode.

    Returns: The mode the user chose
    """

    # Print the options for the user to choose from
    print("Which mode would you like to play in?")
    print("1. Test on Acronyms")
    print("2. Test on Definitions")

    # Get the user's input and validate it
    while (mode := input("Enter 1 or 2: ")) not in [ACRONYM_MODE,
                                                    DEFINITION_MODE]:
        print("Invalid input. Please enter 1 or 2.")

    return mode


def get_number_of_questions(acronyms):
    """
    This function asks the user how many questions they would like to answer.
    The user can choose to use the entire list of acronyms or enter a number
    of questions they would like to answer, which will be randomly selected
    from the list of acronyms.

    Returns: The number of questions the user would like to answer
    """

    # Print the options for the user to choose from
    print("How many questions would you like to answer?")
    print("Enter 'all' to use the entire list of acronyms.")
    print("Enter a number to answer a specific number of questions.")

    # Get the user's input and validate it
    while (number_of_questions := input("Enter a number or 'all': ")) not in \
            ["all"] + [str(i) for i in range(1, len(acronyms) + 1)]:
        print("Invalid input. Please enter a number between 1 and " +
              f"{len(acronyms)} or 'all'.")

    return number_of_questions


def generate_questions(number_of_questions):
    """
    This function generates a dictionary of questions based on the
    user's input.

    Returns: A dictionary of questions
    """

    if number_of_questions == "all":
        return generate_acronym_dictionary()  # Generate the entire dictionary
    else:
        # Generate a random number of questions from the dictionary
        return get_random_questions(int(number_of_questions),
                                    generate_acronym_dictionary())


def get_random_questions(number_of_questions, acronyms):
    """
    This function takes the number of questions the user would like to answer
    and the dictionary of acronyms and definitions and returns a dictionary of
    random questions.

    Returns: A dictionary of random questions
    """
    # Return a dictionary of random questions with comprehension
    return {key: acronyms[key] for key in random.sample(list(acronyms),
                                                        number_of_questions)}


def ask_question(acronym, definition, question_number, mode):
    """
    This function takes a question and the mode and asks the user the question.
    If the mode is 1, the function will display the definition and ask the user
    to input the acronym. If the mode is 2, the function will display the
    acronym and ask the user to input the definition.

    Returns: The user's answer
    """
    if mode == ACRONYM_MODE:
        return input(f"{question_number}. Definition: {definition}\n " +
                     "Enter the acronym: ")
    else:
        return input(f"{question_number}. Acronym: {acronym}\n " +
                     "Enter the definition: ")


def get_correct_answer(acronym, definition, mode):
    """
    This function takes an acronym, definition, and mode and returns the
    correct answer based on the mode.

    Returns: The correct answer
    """
    if mode == ACRONYM_MODE:
        # Check if the definition has a parenthesis and return the acronym
        if "(" in acronym:
            return acronym[:acronym.index("(")].strip()
        else:
            return acronym
    else:
        return definition


def check_answer(user_answer, correct_answer):
    """
    This function takes the user's answer and the correct answer and checks
    if the user's answer is correct. The function will strip the user's answer
    and the correct answer of any leading or trailing whitespace and
    punctuation, remove hyphens, and convert them to lowercase before
    comparing them.

    Returns: True if the user's answer is correct, False if the user's answer
    is incorrect
    """
    # Remove hyphens, punctuation, strip whitespace, and convert to lowercase
    user_answer = user_answer.replace("-", " ").translate(
        str.maketrans("", "", string.punctuation)).strip().lower()
    correct_answer = correct_answer.replace("-", " ").translate(
        str.maketrans("", "", string.punctuation)).strip().lower()

    # Check if the user's answer is correct
    return user_answer == correct_answer


def quiz_user(questions, mode):
    """
    This function quizzes the user on the given questions and returns the score
    and a dictionary of incorrect questions.

    Returns: The score and a dictionary of incorrect questions
    """

    # Initialize variables
    score = 0
    incorrect_questions = {}  # Dictionary to store incorrect questions
    question_number = 1

    # Loop through the questions and quiz the user
    for acronym, definition in questions.items():
        # Ask the user the question
        user_answer = ask_question(acronym, definition, question_number, mode)
        question_number += 1

        # Get the correct answer based on the mode
        correct_answer = get_correct_answer(acronym, definition, mode)

        # Check the user's answer and give feedback
        if check_answer(user_answer, correct_answer):
            score += 1
            print("Correct!\n")
        else:
            # Save incorrect question
            incorrect_questions[acronym] = definition
            print(f"Incorrect! The correct answer is: {correct_answer}\n")

    return score, incorrect_questions


def ask_to_review_questions():
    """
    This function asks the user if they would like to review the questions
    they got incorrect.

    Returns: True if the user would like to review the questions,
    False if the user would not like to review the questions
    """

    # Ask the user if they would like to review the questions
    # Use a Walrus operator to store the user's input and check it
    while (review_questions := input("Would you like to review the " +
                                     "questions you got incorrect? " +
                                     "(yes/no): ")) not in ["yes", "no"]:
        print("Invalid input. Please enter 'yes' or 'no'.")

    if review_questions.lower() == "yes":
        return True
    else:
        return False


def review_incorrect_questions(incorrect_questions, mode):
    """
    This function allows the user to review and re-answer the questions
    they got incorrect.
    """

    # Confirmation Message
    print("\nReviewing incorrect questions...\n")

    # Initialize variables
    question_number = 1
    score = 0

    # Loop through a copy of the incorrect questions
    for acronym, definition in incorrect_questions.copy().items():
        # Ask the user the question
        user_answer = ask_question(acronym, definition,
                                   question_number, mode)

        # Get the correct answer based on the mode
        correct_answer = get_correct_answer(acronym, definition,
                                            mode)

        # Check the user's answer and give feedback
        if check_answer(user_answer, correct_answer):
            del incorrect_questions[acronym]  # Remove the question
            print("Correct!\n")
            score += 1
        else:
            print("Incorrect! The correct answer is: " +
                  f"{correct_answer}\n")

        question_number += 1  # Increment the question number

    # Display the user's score
    print(f"Your score: {score}/{len(incorrect_questions) + score} " +
          f"({score/(len(incorrect_questions) + score):.2%})\n")


# Define the generate_acronymn_dictionary function
def generate_acronym_dictionary():
    """
    This function generates a dictionary of the full list of
    acronymns and definitions that are on the Security+ exam.

    Returns: A dictionary of acronymns and definitions
    """
    # A dictionary of acronyms and their definitions
    acronyms = {
        'AAA': 'Authentication, Authorization, and Accounting',
        'ACL': 'Access Control List',
        'AES': 'Advanced Encryption Standard',
        'AES-256': 'Advanced Encryption Standards 256-bit',
        'AH': 'Authentication Header',
        'AI': 'Artificial Intelligence',
        'AIS': 'Automated Indicator Sharing',
        'ALE': 'Annualized Loss Expectancy',
        'AP': 'Access Point',
        'API': 'Application Programming Interface',
        'APT': 'Advanced Persistent Threat',
        'ARO': 'Annualized Rate of Occurrence',
        'ARP': 'Address Resolution Protocol',
        'ASLR': 'Address Space Layout Randomization',
        'ATT&CK': 'Adversarial Tactics, Techniques, and Common Knowledge',
        'AUP': 'Acceptable Use Policy',
        'AV': 'Antivirus',
        'BASH': 'Bourne Again Shell',
        'BCP': 'Business Continuity Planning',
        'BGP': 'Border Gateway Protocol',
        'BIA': 'Business Impact Analysis',
        'BIOS': 'Basic Input/Output System',
        'BPA': 'Business Partners Agreement',
        'BPDU': 'Bridge Protocol Data Unit',
        'BYOD': 'Bring Your Own Device',
        'CA': 'Certificate Authority',
        'CAPTCHA': 'Completely Automated Public Turing Test to Tell ' +
                   'Computers and Humans Apart',
        'CAR': 'Corrective Action Report',
        'CASB': 'Cloud Access Security Broker',
        'CBC': 'Cipher Block Chaining',
        'CCMP': 'Counter Mode/CBC-MAC Protocol',
        'CCTV': 'Closed-circuit Television',
        'CERT': 'Computer Emergency Response Team',
        'CFB': 'Cipher Feedback',
        'CHAP': 'Challenge Handshake Authentication Protocol',
        'CIA': 'Confidentiality, Integrity, Availability',
        'CIO': 'Chief Information Officer',
        'CIRT': 'Computer Incident Response Team',
        'CMS': 'Content Management System',
        'COOP': 'Continuity of Operation Planning',
        'COPE': 'Corporate Owned, Personally Enabled',
        'CP': 'Contingency Planning',
        'CRC': 'Cyclical Redundancy Check',
        'CRL': 'Certificate Revocation List',
        'CSO': 'Chief Security Officer',
        'CSP': 'Cloud Service Provider',
        'CSR': 'Certificate Signing Request',
        'CSRF': 'Cross-site Request Forgery',
        'CSU': 'Channel Service Unit',
        'CTM': 'Counter Mode',
        'CTO': 'Chief Technology Officer',
        'CVE': 'Common Vulnerability Enumeration',
        'CVSS': 'Common Vulnerability Scoring System',
        'CYOD': 'Choose Your Own Device',
        'DAC': 'Discretionary Access Control',
        'DBA': 'Database Administrator',
        'DDoS': 'Distributed Denial of Service',
        'DEP': 'Data Execution Prevention',
        'DES': 'Digital Encryption Standard',
        'DHCP': 'Dynamic Host Configuration Protocol',
        'DHE': 'Diffie-Hellman Ephemeral',
        'DKIM': 'DomainKeys Identified Mail',
        'DLL': 'Dynamic Link Library',
        'DLP': 'Data Loss Prevention',
        'DMARC': 'Domain Message Authentication Reporting and Conformance',
        'DNAT': 'Destination Network Address Translation',
        'DNS': 'Domain Name System',
        'DoS': 'Denial of Service',
        'DPO': 'Data Privacy Officer',
        'DRP': 'Disaster Recovery Plan',
        'DSA': 'Digital Signature Algorithm',
        'DSL': 'Digital Subscriber Line',
        'EAP': 'Extensible Authentication Protocol',
        'ECB': 'Electronic Code Book',
        'ECC': 'Elliptic Curve Cryptography',
        'ECDHE': 'Elliptic Curve Diffie-Hellman Ephemeral',
        'ECDSA': 'Elliptic Curve Digital Signature Algorithm',
        'EDR': 'Endpoint Detection and Response',
        'EFS': 'Encrypted File System',
        'ERP': 'Enterprise Resource Planning',
        'ESN': 'Electronic Serial Number',
        'ESP': 'Encapsulated Security Payload',
        'FACL': 'File System Access Control List',
        'FDE': 'Full Disk Encryption',
        'FIM': 'File Integrity Management',
        'FPGA': 'Field Programmable Gate Array',
        'FRR': 'False Rejection Rate',
        'FTP': 'File Transfer Protocol',
        'FTPS': 'Secured File Transfer Protocol',
        'GCM': 'Galois Counter Mode',
        'GDPR': 'General Data Protection Regulation',
        'GPG': 'Gnu Privacy Guard',
        'GPO': 'Group Policy Object',
        'GPS': 'Global Positioning System',
        'GPU': 'Graphics Processing Unit',
        'GRE': 'Generic Routing Encapsulation',
        'HA': 'High Availability',
        'HDD': 'Hard Disk Drive',
        'HIDS': 'Host-based Intrusion Detection System',
        'HIPS': 'Host-based Intrusion Prevention System',
        'HMAC': 'Hashed Message Authentication Code',
        'HOTP': 'HMAC-based One-time Password',
        'HSM': 'Hardware Security Module',
        'HTML': 'Hypertext Markup Language',
        'HTTP': 'Hypertext Transfer Protocol',
        'HTTPS': 'Hypertext Transfer Protocol Secure',
        'HVAC': 'Heating, Ventilation Air Conditioning',
        'IaaS': 'Infrastructure as a Service',
        'IaC': 'Infrastructure as Code',
        'IAM': 'Identity and Access Management',
        'ICMP': 'Internet Control Message Protocol',
        'ICS': 'Industrial Control Systems',
        'IDEA': 'International Data Encryption Algorithm',
        'IDF': 'Intermediate Distribution Frame',
        'IdP': 'Identity Provider',
        'IDS': 'Intrusion Detection System',
        'IEEE': 'Institute of Electrical and Electronics Engineers',
        'IKE': 'Internet Key Exchange',
        'IM': 'Instant Messaging',
        'IMAP': 'Internet Message Access Protocol',
        'IoC': 'Indicators of Compromise',
        'IoT': 'Internet of Things',
        'IP': 'Internet Protocol',
        'IPS': 'Intrusion Prevention System',
        'IPSec': 'Internet Protocol Security',
        'IR': 'Incident Response',
        'IRC': 'Internet Relay Chat',
        'IRP': 'Incident Response Plan',
        'ISO': 'International Standards Organization',
        'ISP': 'Internet Service Provider',
        'ISSO': 'Information Systems Security Officer',
        'IV': 'Initialization Vector',
        'KDC': 'Key Distribution Center',
        'KEK': 'Key Encryption Key',
        'L2TP': 'Layer 2 Tunneling Protocol',
        'LAN': 'Local Area Network',
        'LDAP': 'Lightweight Directory Access Protocol',
        'LEAP': 'Lightweight Extensible Authentication Protocol',
        'MaaS': 'Monitoring as a Service',
        'MAC (security policy)': 'Mandatory Access Control',
        'MAC (enables device communication)': 'Media Access Control',
        'MAC (a cryptographic technique)': 'Message Authentication Code',
        'MAN': 'Metropolitan Area Network',
        'MBR': 'Master Boot Record',
        'MD5': 'Message Digest 5',
        'MDF': 'Main Distribution Frame',
        'MDM': 'Mobile Device Management',
        'MFA': 'Multifactor Authentication',
        'MFD': 'Multifunction Device',
        'MFP': 'Multifunction Printer',
        'ML': 'Machine Learning',
        'MMS': 'Multimedia Message Service',
        'MOA': 'Memorandum of Agreement',
        'MOU': 'Memorandum of Understanding',
        'MPLS': 'Multi-protocol Label Switching',
        'MSA': 'Master Service Agreement',
        'MSCHAP': 'Microsoft Challenge Handshake Authentication Protocol',
        'MSP': 'Managed Service Provider',
        'MSSP': 'Managed Security Service Provider',
        'MTBF': 'Mean Time Between Failures',
        'MTTF': 'Mean Time to Failure',
        'MTTR': 'Mean Time to Recover',
        'MTU': 'Maximum Transmission Unit',
        'NAC': 'Network Access Control',
        'NAT': 'Network Address Translation',
        'NDA': 'Non-disclosure Agreement',
        'NFC': 'Near Field Communication',
        'NGFW': 'Next-generation Firewall',
        'NIDS': 'Network-based Intrusion Detection System',
        'NIPS': 'Network-based Intrusion Prevention System',
        'NIST': 'National Institute of Standards & Technology',
        'NTFS': 'New Technology File System',
        'NTLM': 'New Technology LAN Manager',
        'NTP': 'Network Time Protocol',
        'OAUTH': 'Open Authorization',
        'OCSP': 'Online Certificate Status Protocol',
        'OID': 'Object Identifier',
        'OS': 'Operating System',
        'OSINT': 'Open-source Intelligence',
        'OSPF': 'Open Shortest Path First',
        'OT': 'Operational Technology',
        'OTA': 'Over the Air',
        'OVAL': 'Open Vulnerability Assessment Language',
        'P12': 'PKCS #12',
        'P2P': 'Peer to Peer',
        'PaaS': 'Platform as a Service',
        'PAC': 'Proxy Auto Configuration',
        'PAM (idenity security solution)': 'Privileged Access Management',
        'PAM (enables authentication procedures)': 'Pluggable ' +
        'Authentication Modules',
        'PAP': 'Password Authentication Protocol',
        'PAT': 'Port Address Translation',
        'PBKDF2': 'Password-based Key Derivation Function 2',
        'PBX': 'Private Branch Exchange',
        'PCAP': 'Packet Capture',
        'PCI DSS': 'Payment Card Industry Data Security Standard',
        'PDU': 'Power Distribution Unit',
        'PEAP': 'Protected Extensible Authentication Protocol',
        'PED': 'Personal Electronic Device',
        'PEM': 'Privacy Enhanced Mail',
        'PFS': 'Perfect Forward Secrecy',
        'PGP': 'Pretty Good Privacy',
        'PHI': 'Personal Health Information',
        'PII': 'Personally Identifiable Information',
        'PIV': 'Personal Identity Verification',
        'PKCS': 'Public Key Cryptography Standards',
        'PKI': 'Public Key Infrastructure',
        'POP': 'Post Office Protocol',
        'POTS': 'Plain Old Telephone Service',
        'PPP': 'Point-to-Point Protocol',
        'PPTP': 'Point-to-Point Tunneling Protocol',
        'PSK': 'Pre-shared Key',
        'PTZ': 'Pan-tilt-zoom',
        'PUP': 'Potentially Unwanted Program',
        'RA (retrieves encrypted data)': 'Recovery Agent',
        'RA (verifies digital certificate)': 'Registration Authority',
        'RACE': 'Research and Development in Advanced Communications' +
                ' Technologies in Europe',
        'RAD': 'Rapid Application Development',
        'RADIUS': 'Remote Authentication Dial-in User Service',
        'RAID': 'Redundant Array of Inexpensive Disks',
        'RAS': 'Remote Access Server',
        'RAT': 'Remote Access Trojan',
        'RBAC (Job Titles)': 'Role-based Access Control',
        'RBAC (System Admin)': 'Rule-based Access Control',
        'RC4': 'Rivest Cipher version 4',
        'RDP': 'Remote Desktop Protocol',
        'RFID': 'Radio Frequency Identifier',
        'RIPEMD': 'RACE Integrity Primitives Evaluation Message Digest',
        'ROI': 'Return on Investment',
        'RPO': 'Recovery Point Objective',
        'RSA': 'Rivest, Shamir, & Adleman',
        'RTBH': 'Remotely Triggered Black Hole',
        'RTO': 'Recovery Time Objective',
        'RTOS': 'Real-time Operating System',
        'RTP': 'Real-time Transport Protocol',
        'S/MIME': 'Secure/Multipurpose Internet Mail Extensions',
        'SaaS': 'Software as a Service',
        'SAE': 'Simultaneous Authentication of Equals',
        'SAML': 'Security Assertions Markup Language',
        'SAN (specific network environment)': 'Storage Area Network',
        'SAN (digital certificate extension)': 'Subject Alternative Name',
        'SASE': 'Secure Access Service Edge',
        'SCADA': 'Supervisory Control and Data Acquisition',
        'SCAP': 'Security Content Automation Protocol',
        'SCEP': 'Simple Certificate Enrollment Protocol',
        'SD-WAN': 'Software-defined Wide Area Network',
        'SDK': 'Software Development Kit',
        'SDLC': 'Software Development Lifecycle',
        'SDLM': 'Software Development Lifecycle Methodology',
        'SDN': 'Software-defined Networking',
        'SE Linux': 'Security-enhanced Linux',
        'SED': 'Self-encrypting Drives',
        'SEH': 'Structured Exception Handler',
        'SFTP': 'Secured File Transfer Protocol',
        'SHA': 'Secure Hashing Algorithm',
        'SHTTP': 'Secure Hypertext Transfer Protocol',
        'SIEM': 'Security Information and Event Management',
        'SIM': 'Subscriber Identity Module',
        'SLA': 'Service-level Agreement',
        'SLE': 'Single Loss Expectancy',
        'SMS': 'Short Message Service',
        'SMTP': 'Simple Mail Transfer Protocol',
        'SMTPS': 'Simple Mail Transfer Protocol Secure',
        'SNMP': 'Simple Network Management Protocol',
        'SOAP': 'Simple Object Access Protocol',
        'SOAR': 'Security Orchestration, Automation, Response',
        'SoC': 'System on Chip',
        'SOC': 'Security Operations Center',
        'SOW': 'Statement of Work',
        'SPF': 'Sender Policy Framework',
        'SPIM': 'Spam over Internet Messaging',
        'SQL': 'Structured Query Language',
        'SQLi': 'SQL Injection',
        'SRTP': 'Secure Real-Time Protocol',
        'SSD': 'Solid State Drive',
        'SSH': 'Secure Shell',
        'SSL': 'Secure Sockets Layer',
        'SSO': 'Single Sign-on',
        'STIX': 'Structured Threat Information eXchange',
        'SWG': 'Secure Web Gateway',
        'TACACS+': 'Terminal Access Controller Access Control System',
        'TAXII': 'Trusted Automated eXchange of Indicator Information',
        'TCP/IP': 'Transmission Control Protocol/Internet Protocol',
        'TGT': 'Ticket Granting Ticket',
        'TKIP': 'Temporal Key Integrity Protocol',
        'TLS': 'Transport Layer Security',
        'TOC': 'Time-of-check',
        'TOTP': 'Time-based One-time Password',
        'TOU': 'Time-of-use',
        'TPM': 'Trusted Platform Module',
        'TTP': 'Tactics, Techniques, and Procedures',
        'TSIG': 'Transaction Signature',
        'UAT': 'User Acceptance Testing',
        'UAV': 'Unmanned Aerial Vehicle',
        'UDP': 'User Datagram Protocol',
        'UEFI': 'Unified Extensible Firmware Interface',
        'UEM': 'Unified Endpoint Management',
        'UPS': 'Uninterruptable Power Supply',
        'URI': 'Uniform Resource Identifier',
        'URL': 'Universal Resource Locator',
        'USB': 'Universal Serial Bus',
        'USB OTG': 'USB On the Go',
        'UTM': 'Unified Threat Management',
        'UTP': 'Unshielded Twisted Pair',
        'VBA': 'Visual Basic',
        'VDE': 'Virtual Desktop Environment',
        'VDI': 'Virtual Desktop Infrastructure',
        'VLAN': 'Virtual Local Area Network',
        'VLSM': 'Variable Length Subnet Masking',
        'VM': 'Virtual Machine',
        'VoIP': 'Voice over IP',
        'VPC': 'Virtual Private Cloud',
        'VPN': 'Virtual Private Network',
        'VTC': 'Video Teleconferencing',
        'WAF': 'Web Application Firewall',
        'WAP': 'Wireless Access Point',
        'WEP': 'Wired Equivalent Privacy',
        'WIDS': 'Wireless Intrusion Detection System',
        'WIPS': 'Wireless Intrusion Prevention System',
        'WO': 'Work Order',
        'WPA': 'Wi-Fi Protected Access',
        'WPS': 'Wi-Fi Protected Setup',
        'WTLS': 'Wireless TLS',
        'XDR': 'Extended Detection and Response',
        'XML': 'Extensible Markup Language',
        'XOR': 'Exclusive Or',
        'XSRF': 'Cross-site Request Forgery',
        'XSS': 'Cross-site Scripting'
    }

    return acronyms


# Call the main function
if __name__ == "__main__":
    main()

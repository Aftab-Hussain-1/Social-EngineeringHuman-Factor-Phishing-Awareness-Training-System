
from app import create_app, db
from app.models import Question
import io

def import_all_questions():
    app = create_app()
    
    with app.app_context():
        # Read the full CSV file content with all 200 questions
        csv_content = """1	You receive an email asking you to reset your company password. The link looks suspicious. What should you do?	Click the link to reset quickly	Forward the email to IT/security team	Ignore and delete the email	Reply and ask if it's real	B
2	What is the best way to create a secure password?	Use your birthday and favorite color	Use a long, complex mix of characters	Reuse your old password	Use "password123"	B
3	You find a USB drive in the office parking lot. What should you do?	Plug it into your computer to see what's inside	Give it to a coworker	Hand it over to the IT department	Take it home	C
4	Which of the following is an example of phishing?	An IT update from your company domain	An email from HR asking for a survey	An email with a mismatched sender asking for login info	A system notification	C
5	You receive a call from someone claiming to be your bank asking for OTP. What should you do?	Give them the OTP to verify	Hang up and call the official number	Ask them to email you	Tell them your full account details	B
6	What is two-factor authentication (2FA)?	A backup password system	An extra security layer requiring two forms of verification	A password sharing method	A way to reset passwords	B
7	You receive a text message claiming you've won a prize. What should you do?	Click the link immediately	Ignore and delete the message	Forward it to friends	Reply with personal information	B
8	What should you do if you suspect your computer is infected with malware?	Continue using it normally	Disconnect from the internet and scan	Share files with colleagues	Install more software	B
9	Which of these is a sign of a phishing email?	It comes from your boss	It has urgent language and asks for personal info	It contains your company logo	It's sent during business hours	B
10	What is the safest way to connect to public Wi-Fi?	Use any available network	Connect without a password	Use a VPN for protection	Share your connection	C
11	You receive an email asking you to verify your bank account. What should you do?	Click the link and enter details	Log into your bank's official website separately	Call the number in the email	Forward the email to friends	B
12	What is the best practice for software updates?	Never update software	Only update when convenient	Install updates promptly from official sources	Let others update first	C
13	Which password is most secure?	password123	123456789	MyDog'sName2024!	admin	C
14	What should you do if you receive a suspicious attachment?	Open it to see what it contains	Scan it with antivirus before opening	Delete it without opening	Forward it to IT security	D
15	How often should you back up important data?	Once a year	Only when changing computers	Regularly, following a schedule	Never, it's not necessary	C
16	What is social engineering in cybersecurity?	Building social media networks	Manipulating people to reveal confidential information	Creating user-friendly interfaces	Developing social apps	B
17	You get a pop-up saying your computer is infected. What should you do?	Click to fix immediately	Close the pop-up and run your own antivirus	Call the number provided	Download the suggested software	B
18	What is the purpose of a firewall?	To prevent fires in computers	To block unauthorized network access	To speed up internet connection	To store passwords	B
19	Which of these is NOT a good practice for email security?	Using strong passwords	Opening attachments from unknown senders	Enabling two-factor authentication	Being cautious of suspicious links	B
20	What should you do before disposing of an old computer?	Just throw it away	Sell it immediately	Securely wipe all data	Give it to anyone who wants it	C
21	What is ransomware?	Free software	Malware that encrypts files for payment	A type of antivirus	A password manager	B
22	You receive a call asking for your login credentials. What should you do?	Provide them immediately	Hang up and verify through official channels	Ask for their credentials first	Record the conversation	B
23	What is the cloud in computing terms?	Weather-related software	Remote servers accessed via internet	A type of virus	Local storage device	B
24	Which is a sign of a secure website?	It loads quickly	It has colorful graphics	The URL starts with https://	It has many advertisements	C
25	What should you do if you forget your password?	Use a common password	Ask a colleague for theirs	Use the official password reset process	Write it down publicly	C
26	What is phishing?	A hobby involving fish	Attempting to steal sensitive information through deception	A type of computer game	A method of data backup	B
27	How should you handle suspicious emails?	Forward them to everyone	Reply asking for more information	Report them to IT and delete	Keep them for later review	C
28	What is malware?	Helpful software	Malicious software designed to harm systems	A type of hardware	An email service	B
29	Which is the best way to create a strong password?	Use personal information	Make it as short as possible	Use a mix of letters, numbers, and symbols	Use the same password everywhere	C
30	What should you do if your account gets hacked?	Ignore it and hope for the best	Change passwords immediately and report it	Continue using the account	Share the incident on social media	B
31	What is a VPN used for?	Playing games faster	Creating secure connections over the internet	Storing files	Sending emails	B
32	You find a USB drive. What's the safest action?	Plug it in immediately	Scan it with antivirus first	Give it to security/IT department	Use it on a public computer	C
33	What does HTTPS stand for?	HyperText Transfer Protocol Secure	High Technology Transfer Protocol System	HyperText Translation Protocol Service	High Transfer Technology Protocol Standard	A
34	Which is a common sign of a phishing website?	Professional design	Secure payment methods	Spelling and grammar errors	Fast loading speed	C
35	What should you do with old passwords?	Keep using them	Share them with colleagues	Change them regularly	Write them down publicly	C
36	What is spear phishing?	A method of catching fish	General spam emails	Targeted phishing attacks on specific individuals	A type of antivirus software	C
37	How often should you update your passwords?	Never	Only when forced to	Regularly, especially for important accounts	Once a decade	C
38	What is the safest way to shop online?	Use any website you find	Only use websites with HTTPS and good reviews	Share your credit card info freely	Use public Wi-Fi for transactions	B
39	What should you do if you receive a suspicious phone call asking for information?	Provide the information requested	Hang up and call back using official numbers	Ask them to call back later	Give partial information	B
40	What is multi-factor authentication?	Using multiple passwords	Security method requiring multiple forms of verification	A type of malware	A password sharing system	B
41	Which of these is a safe browsing practice?	Clicking on all advertisements	Downloading software from any site	Keeping browser and plugins updated	Disabling security features	C
42	What should you do if you accidentally click a suspicious link?	Continue browsing normally	Close the browser and run a security scan	Click more links to investigate	Share the link with others	B
43	What is a botnet?	A fishing net for bots	Network of infected computers controlled remotely	A type of social network	An antivirus program	B
44	How should you handle company data on personal devices?	Share it freely	Follow company security policies	Store it anywhere convenient	Never use personal devices for work	B
45	What is the purpose of encryption?	To make data faster	To protect data by making it unreadable without a key	To compress files	To backup data	B
46	Which email attachment types are generally risky?	.txt files	.exe, .zip, .scr files	.jpg image files	.pdf documents	B
47	What should you do if you suspect insider threats?	Ignore the situation	Report concerns to appropriate authorities	Confront the person directly	Spread rumors about them	B
48	What is a zero-day vulnerability?	A vulnerability that takes zero days to fix	An unknown security flaw with no available patch	A vulnerability that affects zero people	A daily security update	B
49	How should you verify the identity of someone requesting sensitive information?	Trust them immediately	Use official contact information to verify	Ask for their personal details	Assume they are legitimate	B
50	What is the best practice for using public computers?	Save passwords for convenience	Log out completely and clear browsing data	Leave accounts logged in	Share login credentials	B
51	What should you do if you receive unexpected software update notifications?	Install immediately without checking	Verify the update is legitimate before installing	Ignore all updates	Forward the notification to others	B
52	What is social media privacy important for?	Getting more followers	Protecting personal information from misuse	Posting more content	Making friends online	B
53	Which is a characteristic of a strong security culture?	Employees ignore security policies	Regular security training and awareness	Only IT department handles security	Security is optional	B
54	What should you do if you're working remotely on sensitive data?	Use any available internet connection	Follow company security guidelines and use secure connections	Share credentials with family members	Work in public spaces freely	B
55	What is the risk of using the same password everywhere?	No risk at all	If one account is compromised, all accounts are at risk	It makes passwords stronger	It's more convenient and safe	B
56	How should you handle suspicious network activity?	Ignore it completely	Report it to IT security immediately	Try to investigate yourself	Share it on social media	B
57	What is the purpose of access controls?	To slow down work processes	To ensure only authorized people access specific resources	To make systems more complex	To reduce productivity	B
58	Which is a sign of a compromised email account?	Receiving normal emails	Sent emails you didn't write	Fast email delivery	Good spam filtering	B
59	What should you do before joining a public Wi-Fi network?	Connect immediately	Verify it's legitimate and use security measures	Share the password with others	Use it for banking transactions	B
60	What is the importance of incident reporting?	To blame someone	To help improve security and prevent future incidents	To create more paperwork	To slow down responses	B
61	How should you handle confidential documents?	Share them freely	Follow document classification and handling procedures	Leave them on your desk	Email them to anyone	B
62	What is the risk of downloading software from untrusted sources?	No risk involved	Potential malware infection and security breaches	Faster downloads	Better software quality	B
63	Which authentication method is strongest?	Password only	Password plus SMS	Password plus authenticator app	No authentication	C
64	What should you do if you notice unusual activity on your accounts?	Wait and see what happens	Immediately change passwords and check for unauthorized access	Continue using the account normally	Share the account with others	B
65	What is the purpose of security awareness training?	To waste time	To educate employees about security threats and best practices	To make work more difficult	To reduce productivity	B
66	How should you respond to emergency security notifications?	Ignore them	Follow the instructions promptly and appropriately	Wait for someone else to handle it	Forward to everyone you know	B
67	What is the risk of using outdated software?	No risk at all	Security vulnerabilities that can be exploited	Better performance	Lower costs	B
68	Which is the safest way to dispose of sensitive documents?	Regular trash	Recycling bin	Secure shredding or destruction	Giving them away	C
69	What should you do if you're unsure about a security procedure?	Guess and proceed	Ask for clarification from appropriate authorities	Ignore the procedure	Make up your own procedure	B
70	What is the importance of regular security assessments?	To find blame	To identify and address security weaknesses	To increase costs	To slow down operations	B
71	How should you handle requests for remote access to your computer?	Allow anyone who asks	Verify the request through official channels	Share your screen freely	Give control to strangers	B
72	What is the risk of clicking on suspicious links?	No risk involved	Potential malware download or phishing	Better internet experience	Faster browsing	B
73	Which password manager practice is recommended?	Don't use password managers	Use a reputable password manager with strong master password	Share password manager access	Use weak master passwords	B
74	What should you do if you receive a security alert about your account?	Ignore it completely	Verify the alert through official channels and take appropriate action	Forward it to friends	Click all links in the alert	B
75	What is the purpose of data classification?	To make work harder	To determine appropriate protection levels for different types of data	To reduce data usage	To confuse employees	B
76	How should you handle work-related communications on personal devices?	Mix personal and work freely	Follow company policies for secure communication	Share credentials with family	Use any communication app	B
77	What is the risk of using weak security questions?	No risk at all	Accounts can be easily compromised	Better account recovery	Stronger security	B
78	Which backup strategy is most effective?	Never backup data	Single backup on same device	Multiple backups in different locations (3-2-1 rule)	Backup only once per year	C
79	What should you do if you witness a security violation?	Ignore it	Report it through appropriate channels	Handle it yourself	Spread rumors about it	B
80	What is the importance of keeping software updated?	No importance	Patches security vulnerabilities and improves functionality	Makes software slower	Increases costs	B
81	How should you verify the authenticity of security certificates?	Never check certificates	Check certificate details and issuer	Accept all certificates	Share certificates publicly	B
82	What is the risk of oversharing on social media?	No risk involved	Personal information can be used for social engineering attacks	Better social connections	More privacy	B
83	Which approach to cybersecurity is most effective?	Individual effort only	Layered security approach with multiple defenses	Single security measure	Ignoring security completely	B
84	What should you do if you suspect your device is being monitored?	Continue normal usage	Disconnect and seek IT security assistance	Share more information	Ignore the suspicion	B
85	What is the purpose of security incident response plans?	To create confusion	To provide structured approach to handling security incidents	To slow down responses	To assign blame	B
86	How should you handle security patches and updates?	Install them immediately without testing	Follow organizational patch management procedures	Never install patches	Install only convenient patches	B
87	What is the risk of using public charging stations?	No risk at all	Potential data theft through compromised charging cables	Faster charging	Better battery life	B
88	Which email security practice is most important?	Opening all attachments	Verifying sender identity before acting on requests	Forwarding all emails	Disabling spam filters	B
89	What should you do if you receive conflicting security instructions?	Follow the easiest one	Seek clarification from authorized security personnel	Ignore all instructions	Make your own decision	B
90	What is the importance of security documentation?	To create paperwork	To provide clear guidelines and procedures for security practices	To slow down work	To confuse employees	B
91	How should you respond to suspected phishing attempts?	Engage with the attacker	Report to IT security and delete the message	Forward to colleagues as warning	Reply with fake information	B
92	What is the risk of using default passwords?	No risk involved	Easy targets for attackers who know default credentials	Better security	Easier maintenance	B
93	Which principle should guide data handling decisions?	Share everything freely	Need-to-know basis and data minimization	Collect as much data as possible	Store data indefinitely	B
94	What should you do if you discover a security vulnerability?	Ignore it	Report it through proper channels immediately	Try to exploit it yourself	Share it publicly	B
95	What is the purpose of regular security training?	To waste time	To keep security awareness current and address new threats	To reduce productivity	To create busy work	B
96	How should you handle security tokens or smart cards?	Share them freely	Protect them like physical keys and report if lost	Leave them unattended	Lend them to colleagues	B
97	What is the risk of connecting unknown devices to your network?	No risk at all	Potential malware introduction and network compromise	Better connectivity	Improved performance	B
98	Which approach to password recovery is safest?	Use easily guessable security questions	Use official password recovery through verified channels	Share passwords with colleagues	Write passwords down publicly	B
99	What should you do if you're asked to bypass security procedures?	Always comply	Verify the request and ensure proper authorization	Refuse automatically	Handle it yourself	B
100	What is the importance of exit procedures for departing employees?	No importance	Ensure access is revoked and company assets are returned	Create obstacles	Maintain friendships	B
101	How should you handle suspected malware on your device?	Continue using normally	Isolate the device and report to IT security	Share files before cleaning	Install more software	B
102	What is the risk of using unsecured file sharing services?	No risk involved	Data can be intercepted or accessed by unauthorized parties	Better collaboration	Faster sharing	B
103	Which security awareness topic is most critical for employees?	Technical network configuration	Recognizing and responding to social engineering attacks	Hardware specifications	Software development	B
104	What should you do if you notice unauthorized changes to your accounts?	Ignore small changes	Immediately secure accounts and report the incident	Wait to see what happens	Share account access	B
105	What is the purpose of data loss prevention (DLP) systems?	To delete data	To monitor and prevent unauthorized data transmission	To slow down networks	To create backups	B
106	How should you respond to requests for sensitive information via email?	Provide information immediately	Verify the request through alternative communication channels	Forward the request to others	Ignore the request completely	B
107	What is the risk of using personal cloud storage for work data?	No risk at all	Potential data breaches and policy violations	Better accessibility	Lower costs	B
108	Which factor is most important in creating a security-conscious culture?	Technical complexity	Leadership support and clear policies	Individual effort only	Expensive security tools	B
109	What should you do if you accidentally send sensitive information to wrong recipient?	Hope they don't notice	Immediately contact the recipient and your security team	Send more information to cover up	Do nothing	B
110	What is the importance of regular password audits?	To create work	To identify and address weak or compromised passwords	To slow down systems	To confuse users	B
111	How should you handle security incidents during off-hours?	Wait until business hours	Follow emergency contact procedures immediately	Handle it yourself	Ignore until morning	B
112	What is the risk of using personal devices for work without proper security?	No risk involved	Data breaches and malware spread to corporate networks	Better productivity	Cost savings	B
113	Which communication method is safest for confidential information?	Text messages	Encrypted communication channels approved by organization	Social media	Public forums	B
114	What should you do if you're pressured to ignore security policies?	Always comply with pressure	Report the pressure and follow security policies	Ignore both the pressure and policies	Handle it informally	B
115	What is the purpose of security metrics and monitoring?	To create reports	To measure security effectiveness and detect threats	To slow down operations	To blame individuals	B
116	How should you verify software authenticity before installation?	Install from any source	Check digital signatures and download from official sources	Trust all software	Ask random people	B
117	What is the risk of leaving devices unattended in public?	No risk at all	Physical theft and unauthorized access to data	Better availability	Easier sharing	B
118	Which factor most contributes to successful security programs?	Latest technology only	Employee awareness and adherence to policies	Individual heroics	Expensive tools	B
119	What should you do if you discover colleagues sharing passwords?	Join them	Educate them about risks and report if necessary	Ignore the behavior	Share passwords with them	B
120	What is the importance of business continuity planning in security?	Not important	Ensures operations continue despite security incidents	Creates extra work	Slows down business	B
121	How should you handle requests to install unauthorized software?	Install anything requested	Follow software approval and installation procedures	Install first, ask later	Share installation files	B
122	What is the risk of using weak encryption or no encryption?	No risk involved	Data can be easily intercepted and read by attackers	Better performance	Easier implementation	B
123	Which security control is most effective against insider threats?	Trust everyone completely	Principle of least privilege and monitoring	No controls needed	Physical barriers only	B
124	What should you do if you suspect your communications are being intercepted?	Continue normally	Use alternative secure communication methods and report concerns	Share more information	Ignore the suspicion	B
125	What is the purpose of security awareness campaigns?	To create posters	To reinforce security knowledge and promote good practices	To decorate offices	To waste resources	B
126	How should you respond to social media friend requests from unknown persons?	Accept all requests	Carefully evaluate and decline suspicious requests	Accept but limit access	Share personal information freely	B
127	What is the risk of using outdated security software?	No risk at all	Reduced effectiveness against new threats	Better compatibility	Lower resource usage	B
128	Which approach to security training is most effective?	One-time training only	Regular, interactive, and role-specific training	Technical training only	No training needed	B
129	What should you do if you notice signs of physical surveillance?	Ignore it	Report concerns to security personnel immediately	Confront the suspicious person	Take photos and share	B
130	What is the importance of vendor security assessments?	Not important	Ensures third parties meet security requirements	Creates extra work	Delays projects	B
131	How should you handle security exceptions or variances?	Grant all requests	Follow formal approval processes with risk assessment	Deny all requests	Handle informally	B
132	What is the risk of not having an incident response plan?	No risk involved	Chaotic and ineffective response to security incidents	Better flexibility	Lower costs	B
133	Which factor is most critical for mobile device security?	Screen size	Strong authentication and encryption	Battery life	Processing speed	B
134	What should you do if you're asked to provide access credentials to contractors?	Share your personal credentials	Follow proper access provisioning procedures	Create shared accounts	Ignore the request	B
135	What is the purpose of security risk assessments?	To find fault	To identify and prioritize security risks for mitigation	To create documentation	To delay projects	B
136	How should you respond to reports of security policy violations?	Ignore them	Investigate promptly and take appropriate action	Cover them up	Handle them informally	B
137	What is the risk of inadequate logging and monitoring?	No risk at all	Security incidents may go undetected	Better system performance	Lower storage costs	B
138	Which element is most important in security governance?	Technical expertise only	Clear accountability and decision-making processes	Individual initiatives	Latest technology	B
139	What should you do if you discover unauthorized access to systems?	Wait and observe	Immediately revoke access and investigate	Ignore if no damage visible	Handle privately	B
140	What is the importance of security architecture in system design?	Not important	Integrates security controls from the beginning	Adds unnecessary complexity	Slows development	B
141	How should you handle conflicting security requirements from different stakeholders?	Choose the easiest	Seek guidance from security governance body	Ignore all requirements	Handle case by case	B
142	What is the risk of inadequate security testing?	No risk involved	Vulnerabilities may remain undetected in production	Faster deployment	Lower costs	B
143	Which practice is most important for secure software development?	Speed of development	Integrating security throughout development lifecycle	Individual programmer choice	Latest programming languages	B
144	What should you do if you identify gaps in security controls?	Ignore them	Document and prioritize for remediation	Handle them yourself	Keep them secret	B
145	What is the purpose of security metrics dashboards?	To look impressive	To provide visibility into security posture and trends	To create pretty charts	To confuse stakeholders	B
146	How should you respond to changing threat landscapes?	Ignore changes	Adapt security measures and update threat models	Stick to old methods	Panic about new threats	B
147	What is the risk of poor security communication?	No risk at all	Misunderstanding and poor adherence to security practices	Better creativity	More flexibility	B
148	Which approach to security technology selection is best?	Choose the most expensive	Evaluate based on risk requirements and integration capabilities	Select randomly	Follow competitors	B
149	What should you do if you notice degradation in security controls?	Accept it as normal	Investigate causes and restore effective controls	Work around the issues	Ignore the degradation	B
150	What is the importance of security culture measurement?	Not important	Helps assess and improve organizational security awareness	Creates extra surveys	Wastes time	B
151	How should you handle security budget constraints?	Eliminate all security	Prioritize critical security investments based on risk	Spend on visible items only	Ignore budget limits	B
152	What is the risk of inadequate change management in security?	No risk involved	Security controls may be bypassed or degraded during changes	Faster implementation	More flexibility	B
153	Which factor most influences security decision-making effectiveness?	Personal preferences	Accurate risk information and clear governance	Latest trends	Vendor recommendations	B
154	What should you do if you discover conflicts between security and business objectives?	Always choose business	Seek balanced solutions that address both security and business needs	Always choose security	Ignore the conflict	B
155	What is the purpose of security performance indicators?	To create reports	To measure and improve security program effectiveness	To impress auditors	To justify costs	B
156	How should you respond to security audit findings?	Dispute all findings	Address findings systematically with action plans	Ignore minor findings	Handle informally	B
157	What is the risk of inadequate security resource allocation?	No risk at all	Critical security needs may not be addressed	Better cost control	More flexibility	B
158	Which element is most critical for security program success?	Technology alone	Executive support and organizational commitment	Individual effort	External consultants	B
159	What should you do if you identify systemic security weaknesses?	Keep quiet about them	Develop comprehensive improvement strategies	Fix them piecemeal	Wait for someone else to notice	B
160	What is the importance of security knowledge management?	Not important	Preserves security expertise and enables consistent practices	Creates bureaucracy	Slows down work	B
161	How should you handle security innovation and emerging technologies?	Ignore new technologies	Evaluate security implications before adoption	Adopt everything immediately	Let others go first	B
162	What is the risk of poor security stakeholder engagement?	No risk involved	Lack of support and understanding for security initiatives	Better independence	Fewer meetings	B
163	Which practice most improves security program maturity?	Buying more tools	Continuous improvement based on lessons learned	Following industry trends	Copying competitors	B
164	What should you do if you encounter resistance to security measures?	Force compliance	Understand concerns and address them constructively	Give up on security	Escalate everything	B
165	What is the purpose of security strategy alignment?	To create documents	To ensure security supports business objectives effectively	To impress stakeholders	To justify security budget	B
166	How should you respond to security regulatory changes?	Ignore them until forced	Proactively assess and adapt compliance measures	Panic about implications	Wait for guidance	B
167	What is the risk of inadequate security skills development?	No risk at all	Security capabilities may not keep pace with threats	Lower training costs	More flexibility	B
168	Which factor most affects security program sustainability?	Initial enthusiasm	Ongoing commitment and resource allocation	Latest technology	Industry recognition	B
169	What should you do if you identify gaps between security policy and practice?	Accept the gaps	Work to align practices with policies through training and enforcement	Ignore the differences	Change policies to match practice	B
170	What is the importance of security lessons learned processes?	Not important	Helps prevent recurring security issues and improves responses	Creates extra work	Assigns blame	B
171	How should you handle competing security priorities?	Choose randomly	Use risk-based prioritization with stakeholder input	Handle everything equally	Focus on visible items	B
172	What is the risk of inadequate security communication strategies?	No risk involved	Important security information may not reach intended audiences	Simpler communications	Fewer meetings	B
173	Which approach to security standards adoption is most effective?	Adopt all standards	Select and tailor standards based on organizational needs	Ignore standards completely	Copy other organizations	B
174	What should you do if you discover ineffective security processes?	Live with them	Analyze root causes and implement improvements	Work around them	Blame individuals	B
175	What is the purpose of security program roadmaps?	To look organized	To guide strategic security improvements over time	To satisfy auditors	To justify budgets	B
176	How should you respond to security technology failures?	Panic and blame	Implement contingency plans and investigate causes	Ignore if no immediate impact	Replace with identical technology	B
177	What is the risk of poor security vendor management?	No risk at all	Third-party security failures may impact organization	Lower management overhead	Better relationships	B
178	Which element is most important for security program credibility?	Impressive presentations	Demonstrated effectiveness and consistent delivery	Expensive tools	Industry certifications	B
179	What should you do if you identify security program redundancies?	Keep all redundancies	Optimize for efficiency while maintaining security effectiveness	Eliminate everything duplicate	Ignore redundancies	B
180	What is the importance of security impact assessment?	Not important	Helps understand consequences of security decisions	Creates extra work	Delays decisions	B
181	How should you handle security program scaling challenges?	Stop growing	Develop scalable security architectures and processes	Hire more people	Reduce security requirements	B
182	What is the risk of inadequate security feedback mechanisms?	No risk involved	Security improvements may not address real needs	Simpler processes	Fewer complaints	B
183	Which practice most enhances security program value?	Expensive tools	Demonstrable business value and risk reduction	Industry recognition	Compliance checkmarks	B
184	What should you do if you encounter security program scope creep?	Accept all requests	Manage scope through clear governance and prioritization	Reject everything new	Handle informally	B
185	What is the purpose of security maturity assessments?	To create reports	To identify improvement opportunities and track progress	To satisfy regulators	To justify resources	B
186	How should you respond to security investment decisions?	Choose cheapest options	Base decisions on risk analysis and business value	Follow industry trends	Ask vendors for recommendations	B
187	What is the risk of inadequate security program integration?	No risk at all	Gaps and conflicts between security domains	Better specialization	Clearer responsibilities	B
188	Which factor most determines security program relevance?	Technical sophistication	Alignment with business risks and objectives	Industry best practices	Regulatory requirements	B
189	What should you do if you identify security program blind spots?	Ignore them	Develop strategies to address coverage gaps	Hope they don't matter	Wait for incidents	B
190	What is the importance of security program evolution?	Not important	Keeps security effective against changing threats and business needs	Maintains stability	Reduces complexity	B
191	How should you handle security program resource optimization?	Cut everything equally	Optimize allocation based on risk and effectiveness	Focus on visible areas	Maintain status quo	B
192	What is the risk of static security approaches?	No risk involved	Security may become ineffective against evolving threats	Better predictability	Lower costs	B
193	Which element most contributes to security program resilience?	Single point of control	Diverse and adaptable security capabilities	Rigid processes	Minimal change	B
194	What should you do if you discover security program misalignment?	Accept misalignment	Realign security with business objectives and risk appetite	Change business objectives	Ignore the misalignment	B
195	What is the purpose of security program benchmarking?	To compete	To understand relative performance and identify improvements	To impress stakeholders	To justify current approaches	B
196	How should you respond to security program transformation needs?	Resist all change	Plan and execute systematic improvements	Change everything at once	Wait for external pressure	B
197	What is the risk of inadequate security program documentation?	No risk at all	Knowledge loss and inconsistent security practices	Less paperwork	More flexibility	B
198	Which practice most improves security program effectiveness?	Adding more controls	Regular assessment and continuous improvement	Following checklists	Copying industry leaders	B
199	What should you do if you identify security program inefficiencies?	Accept them as normal	Analyze causes and implement process improvements	Work around them	Blame external factors	B
200	What is the importance of security program legacy management?	Not important	Ensures orderly transition from old to new security approaches	Maintains familiarity	Reduces costs	B"""
        
        # Clear existing questions first
        print("Database already exists.")
        print("Clearing existing questions...")
        Question.query.delete()
        
        # Parse CSV content
        unique_questions = {}
        lines = csv_content.strip().split('\n')
        
        for line in lines:
            if line.strip():
                parts = line.split('\t')
                if len(parts) >= 6:
                    question_text = parts[1].strip()
                    option_a = parts[2].strip()
                    option_b = parts[3].strip()
                    option_c = parts[4].strip()
                    option_d = parts[5].strip()
                    correct_option = parts[6].strip()
                    
                    # Use question text as key to avoid duplicates
                    if question_text not in unique_questions:
                        unique_questions[question_text] = {
                            'text': question_text,
                            'option_a': option_a,
                            'option_b': option_b,
                            'option_c': option_c,
                            'option_d': option_d,
                            'correct_option': correct_option
                        }
        
        # Add unique questions to database
        added_count = 0
        for question_data in unique_questions.values():
            new_question = Question(
                text=question_data['text'],
                option_a=question_data['option_a'],
                option_b=question_data['option_b'],
                option_c=question_data['option_c'],
                option_d=question_data['option_d'],
                correct_option=question_data['correct_option']
            )
            db.session.add(new_question)
            added_count += 1
        
        # Commit changes
        db.session.commit()
        
        print(f"✅ Successfully imported {added_count} unique questions!")
        print(f"📊 Total questions in database: {Question.query.count()}")
        
        # Display sample questions
        print("\n📝 Sample questions added:")
        sample_questions = Question.query.limit(3).all()
        for i, q in enumerate(sample_questions, 1):
            print(f"{i}. {q.text[:50]}... (Answer: {q.correct_option})")

if __name__ == '__main__':
    import_all_questions()

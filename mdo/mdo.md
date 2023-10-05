# Defender for Office 365 - my cheat sheet
## QR code phishing - attack simulation training
It’s in fashion… phishing via QR code 🎣📱, often combined with other techniques like AiTM.

The principle is simple: the targeted user receives an email 📧 with a QR code, a technique that allows to bypass most anti-phishing filters because with images 🖼️, many evasion techniques are possible… The scan of this code redirects the user to a page controlled by the attacker. And this scan is often done with a smartphone 📲, often less secure than the company’s PC 💻…

In the face of such threats, user awareness is therefore paramount! 🚨

Defender for Office 365 includes an attack simulation solution ⚔️, to help you keep your collaborators vigilant. I successfully👍 tested Cam Murray’s solution: https://www.linkedin.com/pulse/performing-unofficial-qr-code-phishing-simulation-ast-cam-murray/ 

Here is the step by step I followed in my case:
- Create a new payload in Attack Simulation Training

>Type:
<img src="ast\01 create payload.png" width="600" alt="Payload creation: type" />

>Name
<img src="ast\02 create payload.png" width="600" alt="Payload creation: name" />

>Configuration
<img src="ast\03 create payload.png" width="600" alt="Payload creation: configuration" />

>Indicators
<img src="ast\04 create payload.png" width="600" alt="Payload creation: indicators" />
- Create a new simulation attaching this payload and optionally training modules
- Launch the simulation
- Here are some screenshots of the user experience

>Email received
<img src="ast\qr code phishin.png" width="600" alt="User experience: email received" />

>Scanning from the phone
<img src="ast\05 user experience.png" width="600" alt="User experience: phone screen after QR code scan" />

>Simulation results in the admin portal
<img src="ast\05 ongoing simulation.png" width="600" alt="Simulation report for the admin" />
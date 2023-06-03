# Email Analysis Tool

Author: [Jeret Christopher@M0du5](https://github.com/jeretc)

This is an email analysis tool that allows you to analyze the headers of an email and extract relevant information for further investigation. The tool provides insights into the sender, recipient, message routing, and potential phishing signs.

## Features

- Analysis of email headers to extract sender and recipient information.
- Detection of potential phishing signs based on header analysis.
- Identification of suspicious links in the email headers (if any).
- Simple and easy-to-use command-line interface.


## Geolocation Accuracy

Please note that the geolocation feature in this tool relies on a free service (e.g., Geopy) to determine the geographical origin of the email based on the received locations. The accuracy of the geolocation may vary and may not always provide precise information. It is recommended to interpret the results with caution and not solely rely on them for conclusive assessments.

If you require more accurate geolocation information, you may consider using a paid geolocation service or implementing a different geolocation method in the code.


## Requirements

- Python 3.x
- Flask (for web-based interface)

## Installation

1. Clone the repository:

```bash
git clone https://github.com/jeretc/email-analysis-tool.git

```

2. pip install -r requirements.txt


## Usage

To use the email analysis tool, follow the steps below:

1. Open a terminal or command prompt.
2. Navigate to the project directory.
3. Run the following command to start the tool:

```bash
python app.py

```

## Web Browser

1. 127.0.0.1:5000/


## License
This project is licensed under the [MIT License](LICENSE).









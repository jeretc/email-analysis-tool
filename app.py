from flask import Flask, render_template, request
from analyze_headers import analyze_email_headers

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        email_headers = request.form['email_headers']
        result = analyze_email_headers(email_headers)  # Call the analysis function
        return render_template('result.html', result=result)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)


from flask import Flask, render_template, request

app = Flask(__name__)

def change_text_case(text, case):
    if case == "lower":
        return text.lower()
    elif case == "upper":
        return text.upper()
    else:
        return text


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/change_case', methods=['GET', 'POST'])
def change_case():
    changed_text = None
    if request.method == 'POST':
        text = request.form['text']
        case = request.form['case']
        changed_text = change_text_case(text, case)
    return render_template('index.html', changed_text=changed_text)

if __name__ == "__main__":
    app.run(debug=True)

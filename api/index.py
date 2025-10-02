from flask import Flask

app = Flask(__name__, static_url_path='')

@app.route('/')
def home():
    return 'Hello, World!'

@app.route('/about')
def about():
    return 'About'

if __name__ == '__main__':
    app.run(debug=True)
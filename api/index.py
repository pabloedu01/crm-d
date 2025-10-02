from flask import Flask, Blueprint
from dotenv import load_dotenv
from api.connetion import create_mongo_client

load_dotenv()

app = Flask(__name__, static_url_path='')

@app.route('/')
def home():
    client = create_mongo_client()
    list_databases = client.list_database_names()
    return str(list_databases)

@app.route('/about')
def about():
    return 'About'

if __name__ == '__main__':
    app.run(debug=True)
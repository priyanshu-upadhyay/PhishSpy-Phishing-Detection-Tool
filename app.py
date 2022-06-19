
from flask import Flask, request, json
from main import main
import sqlite3

app = Flask(__name__)

@app.route('/checkphishing', methods=["POST"])
def checkphishing():
    content_type = request.headers.get('Content-Type')
    if (content_type == 'application/json'):
        json = request.get_json()
        if "url" not in json.keys():
            return {"message" : "parameter missing"}
        url = json["url"]
        try:
            response = main(url)
            return response
        except:
            return {"status-code" : -1, "message" : "Internal Error, admin is notified"}
    else:
        return "Content-Type not supported!"

@app.route('/count')
def checkcount():
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("select count from phishcount where key=1")
    curr_count = cur.fetchall()[0][0]
    conn.close()
    return {"status" : 200, "count": curr_count}






if __name__ == '__main__':

	app.run(debug=True)

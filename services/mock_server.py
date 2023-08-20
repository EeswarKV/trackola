from flask import Flask, jsonify
import json

app = Flask(__name__)

@app.route('/api/stock_table_data')
def mock_data():
    with open('services/data/data.json', 'r') as file:
        print("came inside")
        data = json.load(file)
        return jsonify(data)
    

@app.route('/api/get_fund_manager_data')
def get_fund_manager_data():
    with open('services/data/fund_manager_data.json', 'r') as file:
        data = json.load(file)
        return jsonify(data)
    
@app.route('/api/user_info')
def user_info():
   user= {
       "name": "John Doe",
       "age": 30,
       "isFundManager": True,
   }
   return jsonify(user)

if __name__ == "__main__":
    app.run(port=5001)
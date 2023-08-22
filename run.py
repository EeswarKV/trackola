from multiprocessing import Process
from services.mock_server import app as mock_app  # import the Flask instance of the mock server
import importlib
from src.app import app  # assuming app is the Flask instance in your app.py

def run_app():
    app.run(port=5000)

def run_mock_server():
    mock_app.run(port=5001)

if __name__ == '__main__':
    p1 = Process(target=run_app)
    p2 = Process(target=run_mock_server)

    p1.start()
    p2.start()

    p1.join()
    p2.join()
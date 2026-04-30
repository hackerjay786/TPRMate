import argparse
from app import create_app, init_db_and_seed

parser = argparse.ArgumentParser()
parser.add_argument("--port", type=int, default=5050)
args = parser.parse_args()

app = create_app()

if __name__ == "__main__":
    init_db_and_seed(app)
    app.run(debug=True, port=args.port)

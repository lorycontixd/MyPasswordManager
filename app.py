from mpm.create_app import create_app
import logging
import logging.config


app = create_app()
if __name__ == "__main__":
    app.run(debug=True)
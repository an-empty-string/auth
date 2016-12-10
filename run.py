import os
from app.app import app
import logging
logging.basicConfig(level=logging.DEBUG)
app.run(port=os.getenv("PORT", 5050), debug=True)

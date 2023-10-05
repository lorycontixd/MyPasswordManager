import pathlib
import logging
import logging.config

BASE_PATH = pathlib.Path().resolve()

logging.config.fileConfig('logging.conf')
LOGGER = logging.getLogger('mpm')
print("loaded logger")
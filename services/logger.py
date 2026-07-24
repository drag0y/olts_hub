import logging.handlers


LOGDIR = './'
LOGFILE = 'logging_oltshub.log'

logger = logging.getLogger('OLTsHUB')
logger.setLevel(logging.DEBUG)
logfile = logging.handlers.RotatingFileHandler(f'{LOGDIR}{LOGFILE}', maxBytes=500000, backupCount=3)
logfile.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logfile.setFormatter(formatter)
logger.addHandler(logfile)


def log_write(msg: str):
    '''
    Функция записи логов
    '''
    logger.info(msg)
import os
import sys
import logging
import yaml
import configparser
import shutil
import glob

LOG_FORMAT = '%(asctime)s - %(levelname)s - %(name)s[%(lineno)s][%(filename)s] - %(message)s'
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(LOG_FORMAT))
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(handler)


def main():
    if os.environ.get('DEBUG').upper() == 'TRUE':
        logger.setLevel(logging.DEBUG)

    logger.info("Running build_config.py")
    logger.info("Building hpfeeds config")

    with open('/opt/ihandlers-available/hpfeeds.yaml') as f:
        hpf_config = yaml.safe_load(f)

    logger.debug('Loaded default config: {}'.format(hpf_config))
    # Original YAML config is a list of configs; we only need one
    h = hpf_config[0]
    FEEDS_SERVER = os.environ.get('FEEDS_SERVER').strip('/')
    h['config']['server'] = FEEDS_SERVER
    h['config']['port'] = os.environ.get('FEEDS_SERVER_PORT')
    h['config']['ident'] = os.environ.get('IDENT')
    h['config']['secret'] = os.environ.get('SECRET')
    h['config']['tags'] = [tag for tag in os.environ.get('TAGS').split(',')]
    hpf_config[0] = h

    logger.info("Writing HPFeeds ihandler config...")
    logger.debug('Writing HPFeeds config: {}'.format(h))
    with open("/opt/dionaea/etc/dionaea/ihandlers-enabled/hpfeeds.yaml", 'w') as config_file:
        yaml.safe_dump(hpf_config, config_file)

    S3_OUTPUT_ENABLED = os.environ.get('S3_OUTPUT_ENABLED', False)
    if S3_OUTPUT_ENABLED:
        default_endpoint = "http://" + FEEDS_SERVER + ":8000"
        with open('/opt/ihandlers-available/s3.yaml') as f:
            s3_config = yaml.safe_load(f)
        s = s3_config[0]
        s['config']['access_key_id'] = os.environ.get('S3_ACCESS_KEY')
        s['config']['secret_access_key'] = os.environ.get('S3_SECRET_KEY')
        s['config']['region_name'] = os.environ.get('S3_REGION', 'region')
        s['config']['bucket_name'] = os.environ.get('S3_BUCKET', '')
        s['config']['endpoint_url'] = os.environ.get('S3_ENDPOINT', default_endpoint)
        s['config']['verify'] = os.environ.get('S3_VERIFY', False)
        # Seems to be dionaea specific, as S3 storage doesn't have "folders", just name prepends
        s['config']['s3_dest_folder'] = os.environ.get('S3_DEST_FOLDER', '')
        s3_config[0] = s

        logger.info("Writing S3 ihandler config...")
        logger.debug('Writing S3 config: {}'.format(s))
        with open("/opt/dionaea/etc/dionaea/ihandlers-enabled/s3.yaml", 'w') as config_file:
            yaml.safe_dump(s3_config, config_file)
        logger.info('Successfully wrote S3 config!')
    else:
        logger.info('No S3 configuration enabled. Skipping.')

    # Configure custom personality OR do default configuration
    PERSONALITY = os.environ.get('PERSONALITY', 'default')
    if PERSONALITY != "default":
        logger.info('Found non-default personality: {}'.format(PERSONALITY))
        custom_config = "/opt/personalities/" + PERSONALITY + "/dionaea.cfg"
        if os.path.isfile(custom_config):
            default_config = False
            logger.info('Copying custom dionaea.cfg from {}'.format(custom_config))
            shutil.copyfile(custom_config,'/opt/dionaea/etc/dionaea/dionaea.cfg')
            # Copy any custom ihandlers
            custom_ihandlers = "/opt/personalities/" + PERSONALITY + "/services-available/*.yaml"
            logger.info('Copying custom ihandlers: {}'.format(custom_ihandlers))
            for handler in glob.glob(custom_ihandlers):
                dest_fname = handler.split('/')[-1]
                dest_path = '/opt/dionaea/etc/dionaea/services-enabled/' + dest_fname
                logger.debug('Copying {} to {}'.format(handler,dest_path))
                shutil.copyfile(handler, dest_path)
        else:
            logger.warning('No dionaea.cfg file found for custom personality; using default dionaea.cfg!')
            default_config = True
    else:
        logger.info('Found default personality; using default dionaea.cfg')
        default_config = True

    if default_config:
        try:
            logger.info('Writing default dionaea.cfg file...')
            c = configparser.SafeConfigParser()
            logger.debug('Opening /opt/dionaea/etc/dionaea/dionaea.cfg.orig')
            with open('/opt/dionaea/etc/dionaea/dionaea.cfg.orig', 'r') as f:
                c.read_file(f)
            c['dionaea']['listen.addresses'] = os.environ.get('LISTEN_ADDRESSES', '0.0.0.0')
            c['dionaea']['listen.interfaces'] = os.environ.get('LISTEN_INTERFACES', 'eth0')
            c['dionaea']['default.levels'] = 'all,-debug'
            c['dionaea']['ssl.default.c'] = os.environ.get('DIONAEA_SSL_COUNTRY', 'US')
            c['dionaea']['ssl.default.cn'] = os.environ.get('DIONAEA_SSL_COMMON_NAME', 'test.example.org')
            c['dionaea']['ssl.default.o'] = os.environ.get('DIONAEA_SSL_ORGANIZATION', 'example.org')
            c['dionaea']['ssl.default.ou'] = os.environ.get('DIONAEA_SSL_OU', 'test')


            logger.debug('Preparing to write new dionaea.cfg with [dionaea] values: {}'.format(dict(c['dionaea'])))

            with open('/opt/dionaea/etc/dionaea/dionaea.cfg', 'w') as f:
                c.write(f)

        except Exception as e:
            logger.error('Error configuring dionaea.cfg!: {}'.format(e))
            sys.exit(1)

    logger.info('Finished configuration successfully!')
    sys.exit(0)


if __name__ == "__main__":
    main()


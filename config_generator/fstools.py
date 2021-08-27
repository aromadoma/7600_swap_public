import os
import click
import json
import logging
from config_generator.parameters import SCRIPT_PARAMETERS_PATH, get_script_parameters


def set_homedir(path=None, here=None):
    if path:
        homedir_path = os.path.abspath(path)
    elif here:
        homedir_path = os.getcwd()
    else:
        homedir_path = prompt_homedir_path()

    if click.confirm(f'Установить в качестве домашней \u001b[33m{homedir_path}\u001b[0m?',
                     default=False):
        try:
            set_homedir_parameter(homedir_path)
            create_billing_dir(homedir_path)
            create_readme(homedir_path)
            click.echo(f'\u001b[32mДиректория "{homedir_path}" добавлена.\u001b[0m\n')
            return homedir_path
        except AttributeError:
            click.echo('\u001b[33mВведенная директория совпадает с уже установленной.'
                       '\u001b[0m\n')


def prompt_homedir_path():
    print()
    print('***************************************************************')
    print('**                    ДОМАШНЯЯ ДИРЕКТОРИЯ:                   **')
    print('***************************************************************')

    click.echo('\nДомашняя директория будет использоваться для хранения\n'
               'выгрузок из биллинга, а также сгенерированных скриптом файлов.')
    homedir_path = os.path.abspath(input('\nВведите путь (абсолютный или '
                                         'относительный):\n'))
    return homedir_path


def set_homedir_parameter(path):
    parameters = get_script_parameters()
    if path != parameters.get('homedir'):
        parameters['homedir'] = path
        with open(SCRIPT_PARAMETERS_PATH, 'w') as f:
            json.dump(parameters, f, sort_keys=True, indent=2)
    else:
        raise AttributeError('Введенная директория совпадает с уже установленной')


def create_billing_dir(path):
    billing_path = os.path.join(path, 'billing')
    os.makedirs(billing_path, exist_ok=True)
    return billing_path


def create_logs_dir(path):
    """Create directory for logs if dont exists and return the path"""
    logs_path = os.path.join(path, 'logs')
    os.makedirs(logs_path, exist_ok=True)
    return logs_path


def create_preparing_dir(path):
    """Create directory for parser's table"""
    prep_path = os.path.join(path, 'preparing')
    os.makedirs(prep_path, exist_ok=True)
    return prep_path


def create_check_dir(path):
    """Create directory for parser's table"""
    check_path = os.path.join(path, 'check')
    os.makedirs(check_path, exist_ok=True)
    return check_path


def create_readme(path):
    with open(os.path.join(os.path.dirname(__file__), '.data/readme.txt'), 'r') as f:
        readme_text = f.read()
    with open(os.path.join(path, 'README.txt'), 'w') as f:
        f.write(readme_text)


def get_homedir_path():
    parameters = get_script_parameters()
    if parameters.get('homedir'):
        return parameters.get('homedir')
    elif click.confirm("\u001b[33mДля работы скрипта необходимо указать домашнюю "
                       "директорию. Добавить?\u001b[0m", default=True):
        while True:
            path = set_homedir()
            if path != 1:  # If created
                return path
    else:
        raise AttributeError('Параметр "домашняя директория" не установлен.')


def get_billing_path(hostname):

    logger = logging.getLogger('get_billing_path')
    home_directory = get_homedir_path()
    billing_path = os.path.join(home_directory, f'billing/{hostname}-billing.xlsx')

    # Проверка наличия файлов:
    while True:
        if not os.path.exists(billing_path):
            logger.warning(f'Billing file for {hostname} hasn\'t been found.')
            click.echo('\u001b[31mВНИМАНИЕ:\u001b[0m Файл c выгрузкой из биллинга '
                       'не найден.')
            click.echo(
                f'Убедитесь, что имя файла "billing/{hostname}-billing.xlxs" '
                f'и нажмите Enter для повторной попытки')
            input()
        else:
            break
    return billing_path


def get_config_path(hostname):
    logger = logging.getLogger('get_config_path')
    home_directory = get_homedir_path()
    config_path = os.path.join(home_directory, f'config/{hostname}-configuration.txt')
    if not os.path.exists(config_path):
        logger.warning(f'Config file for {hostname} hasn\'t been found.')
        raise AttributeError(f'Файл конфигурации отсутствует.')
    return config_path


def get_preparing_path(hostname):
    logger = logging.getLogger('get_preparing_path')
    home_directory = get_homedir_path()
    preparing_path = os.path.join(home_directory,
                                  f'preparing/{hostname[:-3]}-preparing.xlsx')
    if not os.path.exists(preparing_path):
        logger.warning(f'Preparing table for {hostname} hasn\'t been found.')
        raise AttributeError(f'Таблица для генерации конфига отсутствует\n'
                             f'{preparing_path}')
    return preparing_path


def get_check_path(pe_location):
    logger = logging.getLogger('get_check_path')
    home_directory = get_homedir_path()
    check_path = os.path.join(home_directory, f'check/{pe_location}-XC')
    if not os.path.exists(check_path):
        logger.warning(f'XC check file for {pe_location} hasn\'t been found.')
        raise AttributeError(f'Файл для проверки XC отсутствует\n{check_path}')
    return check_path


def show_homedir():
    parameters = get_script_parameters()
    if parameters.get('homedir'):
        click.echo('\u001b[32m{}\u001b[0m\n'.format(parameters['homedir']))
    else:
        click.echo('\u001b[32mДомашняя директория не установлена.\u001b[0m\n')

